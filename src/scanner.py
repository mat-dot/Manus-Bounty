from typing import Dict, Any, List

# Lista de cabeçalhos de segurança essenciais e seus valores esperados
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": None, # Apenas verifica a presença, o valor é complexo
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": None, # Apenas verifica a presença
}

def analyze_security_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Analisa os cabeçalhos HTTP de resposta em busca de falhas de segurança comuns.
    Retorna uma lista de vulnerabilidades/falhas encontradas.
    """
    vulnerabilities = []
    
    # Normaliza as chaves dos cabeçalhos para facilitar a pesquisa (case-insensitive)
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    print("\n--- Análise de Cabeçalhos de Segurança ---")

    for header, expected_value_prefix in SECURITY_HEADERS.items():
        lower_header = header.lower()
        
        if lower_header not in normalized_headers:
            vulnerabilities.append({
                "type": "Missing Security Header",
                "severity": "Medium",
                "description": f"O cabeçalho de segurança '{header}' está ausente.",
                "details": f"Este cabeçalho é crucial para mitigar ataques como {header}.",
                "header": header
            })
            print(f"[-] Falha: Cabeçalho {header} ausente.")
        else:
            actual_value = normalized_headers[lower_header]
            
            # Checa se o valor começa com o prefixo esperado (se houver)
            if expected_value_prefix and not actual_value.lower().startswith(expected_value_prefix.lower()):
                 # Exceção para CSP: apenas checa se está presente
                if header == "Content-Security-Policy":
                    print(f"[+] Sucesso: Cabeçalho {header} presente. Valor: {actual_value[:50]}...")
                    continue
                
                vulnerabilities.append({
                    "type": "Weak Security Header Configuration",
                    "severity": "Low",
                    "description": f"O cabeçalho '{header}' está presente, mas com configuração potencialmente fraca.",
                    "details": f"Valor esperado: começar com '{expected_value_prefix}'. Valor atual: '{actual_value}'.",
                    "header": header
                })
                print(f"[!] Aviso: Configuração fraca para {header}.")
            else:
                print(f"[+] Sucesso: Cabeçalho {header} configurado corretamente.")
                
    return vulnerabilities

def run_basic_scan(recon_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Executa a varredura básica de vulnerabilidades com base nas informações do Recon.
    """
    if not recon_info:
        return []

    all_vulnerabilities = []
    
    # 1. Análise de Cabeçalhos de Segurança
    header_vulnerabilities = analyze_security_headers(recon_info.get("headers", {}))
    all_vulnerabilities.extend(header_vulnerabilities)
    
    # 2. Análise de Código de Status
    status_code = recon_info.get("status_code")
    if status_code and status_code >= 400:
        all_vulnerabilities.append({
            "type": "Application Error/Misconfiguration",
            "severity": "Low",
            "description": f"A URL retornou um código de status de erro: {status_code}.",
            "details": f"Códigos de erro (4xx, 5xx) podem indicar páginas não encontradas ou falhas de servidor, o que pode revelar informações por meio de mensagens de erro detalhadas.",
            "status_code": status_code
        })
        print(f"[!] Aviso: Código de status {status_code} recebido.")
    
    # Futuramente, podemos adicionar mais verificações aqui (ex: XSS básico, arquivos sensíveis)
    
    return all_vulnerabilities

if __name__ == '__main__':
    # Exemplo de uso
    sample_headers_good = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "same-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
    }
    sample_headers_bad = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.1 (Unix)"
    }
    
    print("--- Teste de Cabeçalhos Bons ---")
    vulnerabilities_good = analyze_security_headers(sample_headers_good)
    print(f"Vulnerabilidades encontradas: {len(vulnerabilities_good)}")
    
    print("\n--- Teste de Cabeçalhos Ruins ---")
    vulnerabilities_bad = analyze_security_headers(sample_headers_bad)
    print(f"Vulnerabilidades encontradas: {len(vulnerabilities_bad)}")
    for vuln in vulnerabilities_bad:
        print(f"- {vuln['description']}")

