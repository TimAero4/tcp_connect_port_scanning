package portscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// TestPortSpec тестирует логику создания диапазонов и дедупликации портов.
func TestPortSpec(t *testing.T) {
	// Тест обратного диапазона: 100-95 должен дать 6 портов (95, 96, 97, 98, 99, 100)
	ps := Range(100, 95)
	list := ps.List()
	if len(list) != 6 {
		t.Errorf("expected 6 ports for reverse range, got %d", len(list))
	}

	// Тест Merge и дедупликации: 1-5 (5 портов) + 3, 4, 80 (3 уникальных) = 8 портов
	ps2 := Merge(Range(1, 5), Ports(3, 4, 80))
	if len(ps2.ports) != 8 {
		t.Errorf("expected 8 unique ports after merge, got %d", len(ps2.ports))
	}
}

// TestScanOpenPort проверяет успешное TCP-соединение (State = Open).
func TestScanOpenPort(t *testing.T) {
	// Создаем локальный TCP-лисенер на случайном свободном порту (0)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Узнаем, какой порт выделила ОС
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	scanner, err := New(WithConcurrency(10), WithConnectTimeout(1*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Ports(port))
	if err != nil {
		t.Fatal(err)
	}

	for res := range results {
		if res.State != Open {
			t.Errorf("expected port %d to be Open, got %s (err: %v)", port, res.State, res.Err)
		}
		if res.IP.String() != "127.0.0.1" {
			t.Errorf("expected IP 127.0.0.1, got %s", res.IP)
		}
	}
}

// TestScanClosedPort проверяет явно отклоненный порт (State = Closed/Unreachable).
func TestScanClosedPort(t *testing.T) {
	scanner, err := New(WithConcurrency(10), WithConnectTimeout(1*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Порт 2 на localhost почти всегда закрыт и сразу возвращает RST (Connection Refused)
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Ports(2))
	if err != nil {
		t.Fatal(err)
	}

	for res := range results {
		// В зависимости от ОС, закрытый порт может классифицироваться как Closed или Unreachable
		if res.State != Closed && res.State != Unreachable {
			t.Errorf("expected port 2 to be Closed or Unreachable, got %s (err: %v)", res.State, res.Err)
		}
	}
}

// TestScanTimeout проверяет превышение времени ожидания (State = Timeout).
func TestScanTimeout(t *testing.T) {
	// Создаем HTTP-сервер, который принимает соединение, но намеренно задерживает ответ.
	// Это симулирует дроп пакетов файрволом (DROP вместо REJECT).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	// Устанавливаем таймаут подключения меньше, чем задержка сервера
	scanner, err := New(WithConcurrency(10), WithConnectTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, []string{server.Listener.Addr().String()}, Ports(80))
	if err != nil {
		t.Fatal(err)
	}

	for res := range results {
		if res.State != Timeout {
			t.Errorf("expected Timeout, got %s (err: %v)", res.State, res.Err)
		}
	}
}

// TestScanCancellation проверяет корректную остановку через context.Context.
func TestScanCancellation(t *testing.T) {
	scanner, err := New(WithConcurrency(5), WithConnectTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Отменяем контекст вскоре после старта сканирования
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// Сканируем недоступный хост, чтобы подключения висели до таймаута или отмены
	results, err := scanner.Scan(ctx, []string{"192.168.255.1"}, Range(1, 100))
	if err != nil {
		t.Fatal(err)
	}

	canceledOrTimedOutCount := 0
	for res := range results {
		if res.State == Canceled || res.State == Timeout {
			canceledOrTimedOutCount++
		}
	}

	if canceledOrTimedOutCount == 0 {
		t.Error("expected some ports to be canceled or timed out due to context cancellation")
	}
}

// TestGoroutineLeakOnCancel проверяет, что отмена контекста не приводит к утечке горутин.
// Это критически важный тест для конкурентного кода.
func TestGoroutineLeakOnCancel(t *testing.T) {
	// Сохраняем количество горутин до старта
	before := runtime.NumGoroutine()

	scanner, _ := New(WithConcurrency(50), WithConnectTimeout(5*time.Second))
	ctx, cancel := context.WithCancel(context.Background())

	results, _ := scanner.Scan(ctx, []string{"192.168.255.1"}, Range(1, 50))

	// Читаем один результат и отменяем
	<-results
	cancel()

	// Даем время планировщику Goroutine завершить работу
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	// Допускаем погрешность в несколько горутин (сборщик мусора и т.д.),
	// но если разница составляет десятки, значит есть утечка
	if after-before > 5 {
		t.Errorf("potential goroutine leak: before %d, after %d", before, after)
	}
}

// TestEmptyHostsAndPorts проверяет валидацию входных данных.
func TestEmptyHostsAndPorts(t *testing.T) {
	scanner, _ := New()

	_, err := scanner.Scan(context.Background(), []string{}, Ports(80))
	if err == nil {
		t.Error("expected error for empty hosts, got nil")
	}

	_, err = scanner.Scan(context.Background(), []string{"127.0.0.1"}, PortSpec{})
	if err == nil {
		t.Error("expected error for empty ports, got nil")
	}
}

// TestDNSResolutionFailure проверяет обработку несуществующего DNS-имени.
func TestDNSResolutionFailure(t *testing.T) {
	scanner, _ := New(WithConnectTimeout(1 * time.Second))
	results, err := scanner.Scan(context.Background(), []string{"this.domain.does.not.exist.invalid"}, Ports(80))
	if err != nil {
		t.Fatal(err)
	}

	for res := range results {
		if res.State != Error {
			t.Errorf("expected Error state for unresolvable DNS, got %s", res.State)
		}
		if res.Err == nil {
			t.Error("expected an error details for unresolvable DNS")
		}
	}
}

// TestDuplicateHostsAndPorts проверяет дедупликацию целей сканирования.
func TestDuplicateHostsAndPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	scanner, _ := New()

	// Передаем дубликаты хостов и портов
	results, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1", "127.0.0.1"},
		Merge(Ports(port), Ports(port)),
	)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	// Несмотря на дубликаты во входных данных, порт должен быть просканирован только 1 раз
	if count != 1 {
		t.Errorf("expected 1 result for deduplicated inputs, got %d", count)
	}
}

// TestMultipleIPsPerDNS проверяет, что DNS-имя резолвится в несколько IP-адресов.
func TestMultipleIPsPerDNS(t *testing.T) {
	scanner, _ := New(WithConnectTimeout(1 * time.Second))

	// Используем известный DNS Cloudflare, который возвращает два IP: 1.1.1.1 и 1.0.0.1
	results, _ := scanner.Scan(context.Background(), []string{"one.one.one.one"}, Ports(443))

	ips := make(map[string]State)
	for res := range results {
		ips[res.IP.String()] = res.State
	}

	// Ожидаем, что сканер проверил порт 443 на обоих IP-адресах
	if len(ips) < 2 {
		t.Errorf("expected results for at least 2 IPs for one.one.one.one, got %d", len(ips))
	}
}

// TestSlowConsumer проверяет, что сканер не зависнет (deadlock),
// если потребитель перестанет читать из канала результатов при отмене контекста.
func TestSlowConsumer(t *testing.T) {
	scanner, _ := New(WithConcurrency(10), WithConnectTimeout(1*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Сканируем много портов
	results, _ := scanner.Scan(ctx, []string{"127.0.0.1"}, Range(1, 500))

	// Имитируем медленного потребителя
	for res := range results {
		_ = res
		time.Sleep(10 * time.Millisecond)
	}
	// Если реализация некорректна (отсутствует select с ctx.Done() при записи в канал),
	// этот тест зависнет навсегда с фатальной ошибкой (panic: test timed out).
}
