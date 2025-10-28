import requests
from urllib.parse import urlparse
from requests.exceptions import RequestException
import argparse

def validate_url(url: str) -> bool:
    """Valida se a string é uma URL bem formada."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_target_info(url: str) -> dict:
    """
    Realiza uma requisição GET básica para a URL e coleta informações iniciais.
    Retorna o status code, headers e o conteúdo da página.
    """
    if not validate_url(url):
        print(f"URL inválida: {url}")
        return None

    print(f"Iniciando Reconhecimento em: {url}")
    
    try:
        # Configurações para simular um navegador comum e evitar bloqueios
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        info = {
            "url_final": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_preview": response.text[:1024] # Limita o conteúdo para evitar sobrecarga
        }
        
        print(f"Recon concluído. Status: {info['status_code']}")
        return info

    except RequestException as e:
        print(f"Erro ao acessar a URL {url}: {e}")
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Módulo de Reconhecimento Básico para Manus-Bounty.")
    parser.add_argument('-u', '--url', required=True, help='URL do alvo.')
    args = parser.parse_args()
    
    result = get_target_info(args.url)
    if result:
        print("\n--- Resultados do Reconhecimento ---")
        for key, value in result.items():
            print(f"{key}:")
            if key == "headers":
                for h, v in value.items():
                    print(f"  {h}: {v}")
            elif key == "content_preview":
                print(f"  {value}...")
            else:
                print(f"  {value}")

