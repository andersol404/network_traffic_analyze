# Network Traffic Analyzer

Analisa arquivos `.pcap` para identificar tráfego de rede, portas, protocolos,
consultas DNS, requisições HTTP e sinais de atividade suspeita.

A lightweight Python-based network traffic analyzer that reads `.pcap` files and
extracts traffic metadata such as ports, protocols, DNS queries, HTTP requests,
and suspicious activity indicators.

## Quick start / Início rápido

```bash
python3 main.py your_capture.pcap
```

## Output / Saída

The analyzer prints a terminal summary with:
- IPs involved / IPs envolvidos
- Ports / Portas
- Protocols / Protocolos
- DNS queries / Consultas DNS
- HTTP requests / Requisições HTTP
- Suspicious connections / Conexões suspeitas
- Potential C2 indicators / Indicadores de C2

## Notes / Notas

- Keep the `.pcap` file in the same folder as the script.
- Mantenha o arquivo `.pcap` na mesma pasta do script.
- The project is designed for local analysis and terminal output.
- O projeto foi pensado para análise local e saída em terminal.

## Author / Autor
0xander
