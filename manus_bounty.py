import argparse
import json
import os
from urllib.parse import urlparse
from dotenv import load_dotenv
from datetime import datetime

# Importa os módulos core
from src.recon import get_target_info
from src.scanner import run_basic_scan
from src.crawler import crawl_target
from src.fuzzer import fuzz_url
from src.ai_analyze import ai_analyze_vulnerabilities
from src.reporter import generate_markdown_report

# Carrega variáveis de ambiente (como a chave da API)
load_dotenv()

def main():
    """Função principal para orquestrar o Manus-Bounty."""
    
    parser = argparse.ArgumentParser(
        description="Manus-Bounty: Ferramenta de Análise de Segurança Automatizada com IA.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL do alvo (ex: https://exemplo.com).')
    parser.add_argument('-c', '--crawl', action='store_true', help='Ativa o módulo de crawling para descoberta de endpoints.')
    parser.add_argument('-f', '--fuzz', action='store_true', help='Ativa o módulo de fuzzing básico em parâmetros de query.')
    parser.add_argument('-r', '--report', action='store_true', help='Gera um relatório final em formato JSON.')
    parser.add_argument('-a', '--ai-analyze', action='store_true', help='Ativa a análise inteligente com IA (requer chave de API).')
    
    args = parser.parse_args()
    target_url = args.url
    
    print("=====================================================")
    print("  Manus-Bounty: Análise de Segurança com IA")
    print("=====================================================")
    print(f"Alvo: {target_url}\n")
    
    # 1. Módulo Reconhecimento
    print("--- 1. Executando Reconhecimento ---")
    recon_data = get_target_info(target_url)
    
    # 1.1 Módulo Crawler (se ativado)
    discovered_endpoints = []
    if args.crawl:
        print("\n--- 1.1 Executando Crawler ---")
        crawl_results = crawl_target(target_url)
        discovered_endpoints = crawl_results.get("discovered_endpoints", [])
        print(f"Crawler finalizado. {len(discovered_endpoints)} endpoints descobertos.")
        
        # Adiciona os endpoints descobertos para análise posterior
        # Por enquanto, apenas o endpoint principal é analisado pelo scanner/fuzzer
        # Em uma versão mais completa, o scanner/fuzzer iteraria sobre todos os endpoints.
        
    final_results = {
        "target": target_url,
        "recon_data": recon_data,
        "discovered_endpoints": discovered_endpoints,
        "vulnerabilities": [],
        "fuzzing_results": [],
        "ai_analysis": []
    }
    
    if not recon_data:
        print("Falha no Reconhecimento. Encerrando.")
        return

    # 2. Módulo Scanner Básico
    print("\n--- 2. Executando Varredura Básica ---")
    vulnerabilities = run_basic_scan(recon_data)
    final_results["vulnerabilities"].extend(vulnerabilities)
    
    print(f"\n[SCANNER] Varredura concluída. {len(vulnerabilities)} potenciais falhas encontradas.")
    
    # 2.1 Módulo Fuzzer (se ativado)
    fuzzing_results = []
    if args.fuzz:
        print("\n--- 2.1 Executando Fuzzer Básico ---")
        fuzzing_results = fuzz_url(target_url)
        final_results["fuzzing_results"].extend(fuzzing_results)
        print(f"[FUZZER] Fuzzing concluído. {len(fuzzing_results)} resultados de fuzzer encontrados.")
        
    # Combina todos os resultados para a análise de IA
    all_findings = final_results["vulnerabilities"] + final_results["fuzzing_results"]
    
    # 3. Módulo Análise com IA (Será implementado na próxima fase)
    if args.ai_analyze:
        print("\n--- 3. Executando Análise Inteligente com IA ---")

        if 'ai_analyze_vulnerabilities' in globals():
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                print("ERRO: A chave OPENAI_API_KEY não está configurada. Não é possível executar a análise com IA.")
            else:
                # A IA analisará todos os achados combinados (scanner + fuzzer)
                ai_results = ai_analyze_vulnerabilities(all_findings, recon_data)
                final_results["ai_analysis"] = ai_results
                print(f"\n[ANÁLISE IA] Análise concluída. {len(final_results['ai_analysis'])} resultados analisados pela IA.")
        else:
            print("Módulo de IA não encontrado. Ignorando.")
    if args.report:
        # Cria um nome de arquivo seguro a partir da URL
        parsed_url = urlparse(target_url)
        netloc = parsed_url.netloc.replace('.', '_').replace(':', '_')
        
        # 4.1. Relatório JSON (para dados brutos)
        json_report_filename = f"report_{netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_report_filename, 'w', encoding='utf-8') as f:
            json.dump(final_results, f, ensure_ascii=False, indent=4)
        print(f"\n[RELATÓRIO] Dados brutos salvos em: {json_report_filename}")
        
        # 4.2. Relatório Markdown (para formato legível)
        markdown_content = generate_markdown_report(final_results)
        markdown_report_filename = f"report_{netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(markdown_report_filename, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"[RELATÓRIO] Relatório formatado salvo em: {markdown_report_filename}")
        
        # 4.3. (Opcional) Conversão para PDF
        # Para evitar dependências externas, faremos a conversão para PDF na fase de testes, usando o utilitário do sandbox.
        # Por enquanto, o Markdown é o formato principal.
    
    print("\n=====================================================")
    print("  Análise Concluída.")
    print("=====================================================")

if __name__ == '__main__':
    main()

