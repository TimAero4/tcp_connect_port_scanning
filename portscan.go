// Пакет portscan предоставляет функционал для конкурентного TCP Connect-сканирования портов.
// Пакет спроектирован для встраивания в другие Go-приложения и не имеет сторонних зависимостей.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// State представляет структурированное состояние проверенного порта.
// Использование перечисления (enum) вместо сравнения строк ошибок — безопаснее и удобнее для парсинга.
type State int

const (
	Open        State = iota // TCP-соединение успешно установлено
	Closed                   // Соединение явно отклонено целевым хостом (RST)
	Timeout                  // Время ожидания подключения превысило установленный таймаут
	Unreachable              // Сеть или узел недоступны (например, ICMP Destination Unreachable)
	Canceled                 // Операция сканирования была отменена через context.Context
	Error                    // Произошла другая ошибка (невалидный адрес, ошибка DNS и т.д.)
)

// String возвращает строковое представление состояния для удобного вывода.
func (s State) String() string {
	switch s {
	case Open:
		return "open"
	case Closed:
		return "closed"
	case Timeout:
		return "timeout"
	case Unreachable:
		return "unreachable"
	case Canceled:
		return "canceled"
	case Error:
		return "error"
	default:
		return "unknown"
	}
}

// Result содержит результат проверки одного порта на одном хосте/IP.
type Result struct {
	Host     string        // Оригинальное имя хоста или IP, переданное пользователем
	IP       net.IP        // Разрешенный IP-адрес (особенно важно для DNS с несколькими A/AAAA записями)
	Port     uint16        // Номер порта
	State    State         // Структурированное состояние порта
	Duration time.Duration // Время, затраченное на попытку подключения
	Err      error         // Ошибка, если State != Open (может быть nil для Closed в некоторых ОС, но мы сохраняем ошибку соединения)
}

// PortSpec описывает множество портов для сканирования.
// Использование map позволяет автоматически удалять дубликаты портов.
type PortSpec struct {
	ports map[uint16]struct{}
}

// Range создает спецификацию портов из диапазона от start до end (включительно).
// Автоматически обрабатывает обратные диапазоны (например, 1000-1 превращается в 1-1000).
func Range(start, end uint16) PortSpec {
	return RangeList(start, end)
}

// RangeList создает спецификацию из нескольких диапазонов, переданных парами.
// Например: RangeList(1, 1000, 8080, 8080) задаст порты 1-1000 и 8080.
func RangeList(ranges ...uint16) PortSpec {
	ps := PortSpec{ports: make(map[uint16]struct{})}
	if len(ranges) < 2 {
		return ps
	}
	for i := 0; i+1 < len(ranges); i += 2 {
		start, end := ranges[i], ranges[i+1]
		// Обработка обратного диапазона
		if start > end {
			start, end = end, start
		}
		for p := start; p <= end; p++ {
			ps.ports[p] = struct{}{}
		}
	}
	return ps
}

// Ports создает спецификацию из списка отдельных портов.
func Ports(ports ...uint16) PortSpec {
	ps := PortSpec{ports: make(map[uint16]struct{})}
	for _, p := range ports {
		ps.ports[p] = struct{}{}
	}
	return ps
}

// Merge объединяет несколько спецификаций портов в одну, удаляя дубликаты.
func Merge(specs ...PortSpec) PortSpec {
	ps := PortSpec{ports: make(map[uint16]struct{})}
	for _, s := range specs {
		for p := range s.ports {
			ps.ports[p] = struct{}{}
		}
	}
	return ps
}

// Scanner выполняет TCP-сканирование портов с заданными настройками.
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
}

// Option — функция для конфигурации Scanner (Functional Options Pattern).
type Option func(*Scanner) error

// WithConcurrency устанавливает максимальное количество одновременных подключений.
func WithConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n <= 0 {
			return errors.New("concurrency must be greater than 0")
		}
		s.concurrency = n
		return nil
	}
}

// WithConnectTimeout устанавливает таймаут для каждого TCP-подключения.
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) error {
		if d <= 0 {
			return errors.New("connect timeout must be greater than 0")
		}
		s.connectTimeout = d
		return nil
	}
}

// New создает новый экземпляр сканера с применением переданных опций.
func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:    100,             // Значение по умолчанию
		connectTimeout: 3 * time.Second, // Значение по умолчанию
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Scan запускает процесс сканирования переданных хостов и портов.
// Возвращает канал результатов, который автоматически закрывается при завершении сканирования,
// и ошибку валидации входных данных (если хосты/порты пусты).
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSpec) (<-chan Result, error) {
	if len(hosts) == 0 {
		return nil, errors.New("no hosts provided")
	}
	if len(ports.ports) == 0 {
		return nil, errors.New("no ports provided")
	}

	// Дедупликация хостов
	uniqueHosts := make(map[string]struct{})
	for _, h := range hosts {
		uniqueHosts[h] = struct{}{}
	}

	resCh := make(chan Result)

	// Запуск горутины-оркестратора, которая генерирует задания и пишет в канал
	go func() {
		defer close(resCh) // Гарантируем закрытие канала по завершении всех работ

		var wg sync.WaitGroup
		// Семафор для ограничения количества конкурентных подключений
		sem := make(chan struct{}, s.concurrency)

		for host := range uniqueHosts {
			// 1. Сначала резолвим DNS/хост в IP-адреса.
			// Это решает проблему "одно DNS-имя — несколько IP-адресов".
			ips, err := s.resolveHost(ctx, host)
			if err != nil {
				// Если хост не резолвится, отправляем ошибку и пропускаем его порты
				select {
				case resCh <- Result{Host: host, State: Error, Err: err}:
				case <-ctx.Done():
				}
				continue
			}

			for _, ip := range ips {
				for port := range ports.ports {
					// Ранняя остановка отправки заданий, если контекст уже отменен
					if ctx.Err() != nil {
						break
					}

					wg.Add(1)
					sem <- struct{}{} // Занимаем слот в семафоре

					// Запуск горутины для проверки конкретного Host:IP:Port
					go func(host string, ip net.IP, port uint16) {
						defer wg.Done()
						defer func() { <-sem }() // Освобождаем слот в семафоре

						res := s.scanPort(ctx, host, ip, port)

						// Отправка результата в канал.
						// Используем select для предотвращения утечки горутины,
						// если потребитель (читатель из resCh) перестал читать из-за отмены контекста.
						select {
						case resCh <- res:
						case <-ctx.Done():
						}
					}(host, ip, port)
				}
			}
		}

		// Ждем завершения всех горутин сканирования перед закрытием канала
		wg.Wait()
	}()

	return resCh, nil
}

// resolveHost разрешает строку хоста в список net.IP.
func (s *Scanner) resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, errors.New("empty host")
	}

	// Проверяем, не является ли строка уже IP-адресом
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// Выполняем DNS-резолвинг с учетом контекста
	resolver := net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns resolution failed for %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no ip addresses found for %s", host)
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

// scanPort выполняет попытку TCP-подключения и маппит ошибку на структурированный State.
func (s *Scanner) scanPort(ctx context.Context, host string, ip net.IP, port uint16) Result {
	target := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	start := time.Now()

	// Создаем дочерний контекст с таймаутом для конкретного подключения
	dialCtx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", target)
	duration := time.Since(start)

	res := Result{
		Host:     host,
		IP:       ip,
		Port:     port,
		Duration: duration,
	}

	if err == nil {
		// Соединение установлено. Сразу закрываем, так как нам нужно только проверить доступность.
		conn.Close()
		res.State = Open
		return res
	}

	// Маппинг ошибки на State. Строго запрещено определять состояние через сравнение текста ошибки.
	// Мы используем интерфейсы стандартной библиотеки (errors.Is, errors.As, net.Error).
	res.Err = err

	if errors.Is(err, context.Canceled) {
		res.State = Canceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		res.State = Timeout
	} else {
		// Проверяем, является ли ошибка сетевой (net.Error)
		var netErr net.Error
		if errors.As(err, &netErr) {
			if netErr.Timeout() {
				// Таймаут самого сокета (в отличие от контекста)
				res.State = Timeout
			} else {
				// Ошибка сети без таймаута (как правило, Connection Refused или Unreachable)
				// В Go "connection refused" возвращает *net.OpError, который реализует net.Error, но Timeout() == false
				res.State = Unreachable
			}
		} else {
			// Остальные ошибки (например, невалидный формат адреса)
			res.State = Error
		}
	}

	return res
}
