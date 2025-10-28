import json
from typing import Dict, Any, List
from datetime import datetime

def generate_markdown_report(results: Dict[str, Any]) -> str:
    """
    Gera um relatório de segurança em formato Markdown a partir dos resultados da análise.
    """
    
    target_url = results.get("target", "N/A")
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    markdown = f"# Relatório de Análise de Segurança - Manus-Bounty\n\n"
    markdown += f"**Alvo:** {target_url}\n"
    markdown += f"**Data da Análise:** {report_date}\n\n"
    markdown += "---\n\n"

    # --- 1. Seção de Reconhecimento ---
    markdown += "## 1. Dados de Reconhecimento\n\n"
    recon_data = results.get("recon_data", {})
    
    markdown += "| Chave | Valor |\n"
    markdown += "| :--- | :--- |\n"
    markdown += f"| URL Final | {recon_data.get('url_final', 'N/A')} |\n"
    markdown += f"| Status HTTP | {recon_data.get('status_code', 'N/A')} |\n"
    
    markdown += "\n### 1.1. Cabeçalhos de Resposta\n\n"
    headers = recon_data.get("headers", {})
    if headers:
        markdown += "| Cabeçalho | Valor |\n"
        markdown += "| :--- | :--- |\n"
        for key, value in headers.items():
            markdown += f"| `{key}` | `{value}` |\n"
    else:
        markdown += "Nenhum cabeçalho de resposta encontrado.\n"
        
    discovered_endpoints = results.get("discovered_endpoints", [])
    if discovered_endpoints:
        markdown += "\n### 1.2. Endpoints Descobertos (Crawler)\n\n"
        markdown += f"Foram descobertos **{len(discovered_endpoints)}** endpoints através do crawling.\n\n"
        markdown += "```\n"
        markdown += "\n".join(discovered_endpoints[:20]) # Limita a exibição
        if len(discovered_endpoints) > 20:
            markdown += f"\n... e mais {len(discovered_endpoints) - 20} endpoints."
        markdown += "\n```\n"

    markdown += "\n---\n\n"

    # --- 2. Seção de Vulnerabilidades e Falhas ---
    markdown += "## 2. Achados de Segurança (Scanner & Fuzzer)\n\n"
    
    all_findings = results.get("vulnerabilities", []) + results.get("fuzzing_results", [])
    
    if not all_findings:
        markdown += "Nenhuma falha de segurança básica ou indicação de vulnerabilidade foi encontrada pelo scanner/fuzzer.\n"
    else:
        markdown += f"Total de **{len(all_findings)}** achados brutos (antes da análise de IA).\n\n"
        
        for i, finding in enumerate(all_findings):
            markdown += f"### 2.{i+1}. Achado: {finding.get('type', 'Achado Desconhecido')}\n\n"
            markdown += f"**Severidade Bruta:** {finding.get('severity', 'N/A')}\n\n"
            markdown += f"**Descrição:** {finding.get('description', 'N/A')}\n\n"
            
            details = finding.get('details', '')
            if details:
                markdown += f"**Detalhes:** {details}\n\n"

    markdown += "\n---\n\n"

    # --- 3. Seção de Análise de IA ---
    markdown += "## 3. Análise Inteligente de IA\n\n"
    ai_analysis = results.get("ai_analysis", [])
    
    if not ai_analysis:
        markdown += "A análise de IA não foi executada ou não retornou resultados.\n"
    else:
        markdown += f"A IA analisou **{len(ai_analysis)}** achados e forneceu *insights* e **mitigações**.\n\n"
        
        for i, analysis in enumerate(ai_analysis):
            markdown += f"### 3.{i+1}. Análise de Vulnerabilidade\n\n"
            markdown += f"**Falha Original:** {analysis.get('original_vulnerability', 'N/A')}\n\n"
            markdown += f"**Severidade Reavaliada (IA):** **{analysis.get('ai_severity', 'N/A')}**\n\n"
            markdown += f"**Resumo da Implicação (IA):**\n"
            markdown += f"> {analysis.get('ai_summary', 'N/A')}\n\n"
            markdown += f"**Sugestões de Mitigação (IA):**\n"
            markdown += f"```\n{analysis.get('ai_mitigation', 'N/A')}\n```\n\n"
            
    markdown += "\n---\n\n"
    markdown += "## 4. Conclusão e Uso Ético\n\n"
    markdown += "Este relatório foi gerado pelo Manus-Bounty com o objetivo de auxiliar na **identificação defensiva** de falhas de segurança. Todos os achados devem ser **verificados manualmente** e reportados de acordo com as diretrizes do programa de Bug Bounty ou política de segurança do alvo.\n\n"
    markdown += "**Lembre-se:** O uso desta ferramenta deve ser **sempre ético e autorizado**.\n"

    return markdown

if __name__ == '__main__':
    # Exemplo de uso (simulação)
    simulated_results = {
        "target": "https://simulated-target.com",
        "recon_data": {
            "url_final": "https://simulated-target.com/home",
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                "Server": "Apache",
                "X-Frame-Options": "SAMEORIGIN"
            },
            "content_preview": "<html>..."
        },
        "discovered_endpoints": [
            "https://simulated-target.com/about",
            "https://simulated-target.com/contact",
            "https://simulated-target.com/login",
            "https://simulated-target.com/api/v1/users"
        ],
        "vulnerabilities": [
            {
                "type": "Missing Security Header",
                "severity": "Medium",
                "description": "O cabeçalho de segurança 'Strict-Transport-Security' está ausente.",
                "details": "Este cabeçalho é crucial para mitigar ataques de downgrade de protocolo.",
                "header": "Strict-Transport-Security"
            }
        ],
        "fuzzing_results": [
            {
                "type": "Input Reflection (Potential XSS/Injection)",
                "severity": "Medium",
                "description": "O payload '\"' foi refletido no corpo da página ao ser injetado no parâmetro 'id'.",
                "details": "URL fuzzed: https://simulated-target.com/page?id=\"",
                "param": "id",
                "payload": "\""
            }
        ],
        "ai_analysis": [
            {
                "original_vulnerability": "O cabeçalho de segurança 'Strict-Transport-Security' está ausente.",
                "ai_severity": "High",
                "ai_summary": "A ausência do cabeçalho HSTS expõe o usuário a ataques de downgrade de protocolo (SSL Stripping) e garante que a comunicação não seja forçada a usar HTTPS.",
                "ai_mitigation": "Configure o servidor web para incluir o cabeçalho 'Strict-Transport-Security' com um 'max-age' longo (ex: 31536000) e a diretiva 'includeSubDomains'."
            }
        ]
    }
    
    markdown_output = generate_markdown_report(simulated_results)
    print(markdown_output)

