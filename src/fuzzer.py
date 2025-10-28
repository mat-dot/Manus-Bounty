import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from typing import List, Dict, Any

# Payloads de fuzzer básicos e éticos para detecção de reflexão e erros
FUZZING_PAYLOADS = [
    "FUZZ_TEST_STRING_123",
    "'",
    "\"",
    "<",
    ">",
    "<!--",
    "//",
    "../",
    "\\",
    "0",
    "-1",
    "1337",
]

def fuzz_url(url: str) -> List[Dict[str, Any]]:
    """
    Realiza um fuzzer básico em todos os parâmetros de consulta (query parameters) de uma URL.
    Foca em identificar reflexão de input (potencial XSS) ou erros de servidor.
    """
    
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    fuzzing_results = []
    
    if not query_params:
        # print(f"URL {url} não possui parâmetros de consulta para fuzzing.")
        return []
    
    print(f"Iniciando Fuzzing em {len(query_params)} parâmetros da URL: {url}")

    for param, values in query_params.items():
        original_value = values[0] # Fuzza apenas o primeiro valor do parâmetro
        
        for payload in FUZZING_PAYLOADS:
            # Constrói a nova query com o payload
            new_query_params = query_params.copy()
            new_query_params[param] = [payload]
            
            new_query = urlencode(new_query_params, doseq=True)
            fuzzed_url = urlunparse(parsed_url._replace(query=new_query))
            
            try:
                # Faz a requisição GET com o payload
                response = requests.get(fuzzed_url, timeout=5)
                
                # 1. Checa por reflexão do payload no corpo da resposta
                if payload in response.text:
                    fuzzing_results.append({
                        "type": "Input Reflection (Potential XSS/Injection)",
                        "severity": "Medium",
                        "description": f"O payload '{payload}' foi refletido no corpo da página ao ser injetado no parâmetro '{param}'.",
                        "details": f"URL fuzzed: {fuzzed_url}",
                        "param": param,
                        "payload": payload
                    })
                
                # 2. Checa por códigos de status de erro de servidor (5xx)
                if 500 <= response.status_code < 600:
                     fuzzing_results.append({
                        "type": "Server Error Indication",
                        "severity": "Low",
                        "description": f"O payload '{payload}' causou um erro de servidor (HTTP {response.status_code}) ao ser injetado no parâmetro '{param}'.",
                        "details": f"URL fuzzed: {fuzzed_url}",
                        "param": param,
                        "payload": payload
                    })

            except requests.RequestException as e:
                # print(f"  [ERRO] Falha ao acessar {fuzzed_url}: {e}")
                pass # Ignora erros de conexão/timeout para não parar o fuzzer
                
    print(f"Fuzzing concluído. {len(fuzzing_results)} resultados de fuzzer encontrados.")
    return fuzzing_results

if __name__ == '__main__':
    # Exemplo de uso (requer um site real para funcionar)
    # results = fuzz_url("https://test.com/search?q=test&page=1")
    # print(json.dumps(results, indent=4))
    print("Módulo Fuzzer. Para testar, use o arquivo principal 'manus_bounty.py'.")

