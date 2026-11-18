# tcp_connect_port_scanning
A Go package for concurrent TCP Connect port scanning. It is designed to be embedded in another Go applications without relying on CLI, HTTP frameworks, or external dependencies.

## Features

- Классическое TCP сканирование с использованием стандартной библиотеки Go.
- Конкурентное сканирование с настраиваемым ограничением количества одновременных подключений.
- Поддержка IPv4
- Гибкое указание портов: списки, диапазоны
- Структурированные состояния портов (`Open`, `Closed`, `Timeout`, `Unreachable`, `Canceled`, `Error`)


## Usage

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/yourusername/portscan"
)

func main() {
    // Создание экземпляра сканера с настройками
    scanner, err := portscan.New(
        portscan.WithConcurrency(100),
        portscan.WithConnectTimeout(500*time.Millisecond),
    )
    if err != nil {
        panic(err)
    }

    // Настройка портов: диапазон 1-1000 плюс отдельные порты 8080 и 8443
    ports := portscan.Merge(
        portscan.Range(1, 1000),
        portscan.Ports(8080, 8443),
    )

    // Запуск сканирования
    results, err := scanner.Scan(
        context.Background(),
        []string{"192.168.1.10", "localhost"},
        ports,
    )
    if err != nil {
        panic(err)
    }

    // Чтение результатов из канала
    for result := range results {
        fmt.Printf("%s (%s):%d %s (время: %v)\n",
            result.Host,
            result.IP,
            result.Port,
            result.State,
            result.Duration,
        )
    }
}