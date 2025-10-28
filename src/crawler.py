import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Set, Dict, Any

def is_valid(url: str) -> bool:
    """Verifica se a URL é válida e bem formada."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_links(url: str, content: str) -> Set[str]:
    """Extrai todos os links de uma página HTML."""
    soup = BeautifulSoup(content, 'html.parser')
    hrefs = set()
    
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue
        
        # Converte para URL absoluta
        href = urljoin(url, href)
        
        # Remove fragmentos de URL (ex: #section)
        parsed_href = urlparse(href)
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path + "?" + parsed_href.query
        
        if is_valid(href):
            hrefs.add(href)
            
    return hrefs

def crawl_target(base_url: str, max_depth: int = 1, max_links: int = 50) -> Dict[str, Any]:
    """
    Realiza um crawling limitado no alvo para descobrir URLs e endpoints.
    A profundidade e o número de links são limitados para uso ético e evitar sobrecarga.
    """
    
    # Normaliza a URL base para garantir que apenas links do mesmo domínio sejam seguidos
    base_netloc = urlparse(base_url).netloc
    
    # Conjunto de links já visitados
    visited_links = set()
    # Fila de links a serem visitados (link, profundidade)
    links_to_visit = [(base_url, 0)]
    # Links descobertos
    discovered_endpoints = set()
    
    print(f"Iniciando Crawling em {base_url} (Profundidade Máx: {max_depth}, Links Máx: {max_links})")
    
    while links_to_visit and len(discovered_endpoints) < max_links:
        current_url, depth = links_to_visit.pop(0)
        
        if current_url in visited_links:
            continue
        
        if depth > max_depth:
            continue
            
        # Verifica se o link pertence ao domínio alvo
        if urlparse(current_url).netloc != base_netloc:
            continue
        
        visited_links.add(current_url)
        discovered_endpoints.add(current_url)
        
        try:
            print(f"  [D{depth}] Visitando: {current_url}")
            response = requests.get(current_url, timeout=5, allow_redirects=True)
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                new_links = get_all_links(current_url, response.text)
                
                for link in new_links:
                    if link not in visited_links and urlparse(link).netloc == base_netloc:
                        links_to_visit.append((link, depth + 1))
                        
        except requests.RequestException as e:
            print(f"  [ERRO] Falha ao acessar {current_url}: {e}")
            
    print(f"Crawling concluído. {len(discovered_endpoints)} endpoints descobertos.")
    
    return {
        "base_url": base_url,
        "discovered_endpoints": list(discovered_endpoints)
    }

if __name__ == '__main__':
    # Exemplo de uso (requer um site real para funcionar)
    # results = crawl_target("http://testphp.vulnweb.com", max_depth=1)
    # print(json.dumps(results, indent=4))
    print("Módulo Crawler. Para testar, use o arquivo principal 'manus_bounty.py'.")

