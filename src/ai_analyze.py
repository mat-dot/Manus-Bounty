import os
import json
from typing import List, Dict, Any
from openai import OpenAI
from openai import APIError

# O modelo gpt-4.1-mini é uma opção de alto desempenho e baixo custo
LLM_MODEL = "gpt-4.1-mini" 

def ai_analyze_vulnerabilities(vulnerabilities: List[Dict[str, Any]], recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Usa um LLM para analisar as vulnerabilidades encontradas e sugerir mitigação.
    """
    
    if not vulnerabilities:
        print("Nenhuma vulnerabilidade encontrada para análise de IA.")
        return []

    print(f"Enviando {len(vulnerabilities)} falhas para análise inteligente com {LLM_MODEL}...")

    # Prepara o prompt com as informações do alvo e as vulnerabilidades
    recon_summary = {
        "url_final": recon_data.get("url_final"),
        "status_code": recon_data.get("status_code"),
        "headers_keys": list(recon_data.get("headers", {}).keys())
    }
    
    # Remove o conteúdo HTML do recon_data para economizar tokens e focar na estrutura
    recon_data_for_prompt = recon_summary
    
    # Formata as vulnerabilidades em texto para o LLM
    vulnerabilities_text = json.dumps(vulnerabilities, indent=2, ensure_ascii=False)

    system_prompt = (
        "Você é um analista de segurança sênior e ético. Sua tarefa é analisar "
        "uma lista de potenciais falhas de segurança encontradas por um scanner básico "
        "em uma aplicação web. Seu foco deve ser em **análise defensiva** e **mitigação**. "
        "Para cada falha, você deve fornecer uma análise concisa e objetiva, "
        "seguindo o formato JSON estrito. "
        "**NUNCA** sugira métodos de exploração."
    )

    user_prompt = f"""
    Analise as seguintes falhas encontradas pelo scanner:

    --- Dados do Alvo (Recon) ---
    {json.dumps(recon_data_for_prompt, indent=2)}

    --- Falhas Encontradas (Scanner) ---
    {vulnerabilities_text}

    Para cada item na lista 'vulnerabilities', gere um novo objeto JSON com as seguintes chaves:
    1. 'original_vulnerability': A descrição original da falha.
    2. 'ai_severity': Uma reavaliação da severidade (Info, Low, Medium, High).
    3. 'ai_summary': Um resumo da implicação de segurança em português.
    4. 'ai_mitigation': Sugestões de mitigação e correção em português, focadas em boas práticas de desenvolvimento e configuração.

    O resultado DEVE ser um array JSON contendo apenas os novos objetos de análise.
    """
    
    try:
        client = OpenAI()
        
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        # O modelo deve retornar um objeto JSON, mas o conteúdo real é uma string
        ai_response_content = response.choices[0].message.content
        
        # O LLM deve retornar um array JSON, mas o response_format={"type": "json_object"}
        # força a saída a ser um objeto. Vamos tentar carregar a string como JSON.
        try:
            # Tenta carregar o JSON diretamente
            ai_analysis_results = json.loads(ai_response_content)
            
            # Se o LLM retornou um objeto com uma chave que contém o array, extrai
            if isinstance(ai_analysis_results, dict) and len(ai_analysis_results) == 1:
                # Assume que o único valor no objeto é o array de resultados
                return list(ai_analysis_results.values())[0]
            
            # Se for um array diretamente
            if isinstance(ai_analysis_results, list):
                return ai_analysis_results
            
            # Se for um objeto que precisa ser envolvido em um array (caso de uma única vulnerabilidade)
            if isinstance(ai_analysis_results, dict):
                 return [ai_analysis_results]
            
            print("Aviso: O LLM não retornou um array JSON válido. Retornando resultado bruto.")
            return [{"error": "Formato de resposta do LLM inválido", "raw_response": ai_response_content}]

        except json.JSONDecodeError as e:
            print(f"ERRO: Falha ao decodificar a resposta JSON do LLM: {e}")
            print(f"Resposta bruta: {ai_response_content[:500]}...")
            return [{"error": "Falha na decodificação JSON", "details": str(e), "raw_response_preview": ai_response_content[:500]}]

    except APIError as e:
        print(f"ERRO de API OpenAI: {e}")
        return [{"error": "Falha na comunicação com a API de IA", "details": str(e)}]
    except Exception as e:
        print(f"ERRO inesperado na análise de IA: {e}")
        return [{"error": "Erro interno na análise de IA", "details": str(e)}]

if __name__ == '__main__':
    # Exemplo de uso (simulação)
    simulated_vulnerabilities = [
        {
            "type": "Missing Security Header",
            "severity": "Medium",
            "description": "O cabeçalho de segurança 'Strict-Transport-Security' está ausente.",
            "details": "Este cabeçalho é crucial para mitigar ataques como Strict-Transport-Security.",
            "header": "Strict-Transport-Security"
        },
        {
            "type": "Missing Security Header",
            "severity": "Medium",
            "description": "O cabeçalho de segurança 'X-Frame-Options' está ausente.",
            "details": "Este cabeçalho é crucial para mitigar ataques como X-Frame-Options.",
            "header": "X-Frame-Options"
        }
    ]
    simulated_recon_data = {
        "url_final": "https://exemplo.com",
        "status_code": 200,
        "headers": {"Content-Type": "text/html"},
        "content_preview": "<html>..."
    }
    
    # Para testar, você precisará de uma chave de API válida no ambiente
    # os.environ["OPENAI_API_KEY"] = "SUA_CHAVE_DE_TESTE"
    if os.getenv("OPENAI_API_KEY"):
        results = ai_analyze_vulnerabilities(simulated_vulnerabilities, simulated_recon_data)
        print("\n--- Resultados da Análise de IA (Simulação) ---")
        print(json.dumps(results, indent=4, ensure_ascii=False))
    else:
        print("Chave OPENAI_API_KEY não configurada. Não é possível executar o teste de IA.")

