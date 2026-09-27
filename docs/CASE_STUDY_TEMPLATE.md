# Case técnico — Plataforma de triagem CTI

## 1. Objetivo

Desenvolver uma solução capaz de receber um hash, consultar fontes externas de
Cyber Threat Intelligence, normalizar as evidências, realizar triagem de
malware e produzir um relatório operacional para SOC, DFIR, threat hunting e
engenharia de detecção.

## 2. Problema

A análise manual de um artefato exige consultas em fontes diferentes,
comparação de classificações, extração de IOCs, avaliação de comportamentos e
registro das conclusões. Esse processo pode ser lento, inconsistente e pouco
rastreável.

O case automatiza as etapas repetitivas mantendo separação entre fatos
observados, inferências e lacunas de inteligência.

## 3. Escopo

### Incluído

- Hashes MD5, SHA-1 e SHA-256.
- VirusTotal e MalwareBazaar.
- Análise determinística.
- GenAI opcional com Claude ou OpenAI.
- LangGraph para orquestração.
- SQLite e CSV.
- API FastAPI.
- Relatório JSON e HTML.
- Frontend web.
- Docker e testes.

### Fora do escopo

- Execução direta de malware.
- Upload automático de amostras.
- Bloqueio automático em controles corporativos.
- Atribuição definitiva de ator de ameaça.
- Exposição pública sem autenticação.

## 4. Requisitos de inteligência

| PIR | Questão |
|---|---|
| PIR-001 | O artefato deve ser tratado como malicioso ou suspeito? |
| PIR-002 | Qual família de malware é sustentada pelas evidências? |
| PIR-003 | Quais comportamentos e TTPs foram observados? |
| PIR-004 | Existe infraestrutura de rede ou C2 associada? |
| PIR-005 | Quais ações defensivas devem ser priorizadas? |

## 5. Arquitetura

Descrever:

- Entrada do hash.
- Coleta paralela.
- Normalização.
- Baseline determinística.
- Decisão de uso da GenAI.
- Grounding.
- Persistência.
- Disseminação em JSON, CSV e HTML.

Utilizar o diagrama presente no `README.md`.

## 6. Implementação

### 6.1 Modelos e validação

Registrar como os modelos Pydantic validam hash, provedores, evidências,
observáveis, famílias, TTPs e recomendações.

### 6.2 Integrações

Documentar:

- Endpoint utilizado por cada provedor.
- Autenticação.
- Timeout.
- Tratamento de `404`, `403`, `429` e erros de rede.
- Dados normalizados.

### 6.3 Análise determinística

Explicar os limiares de classificação, o consenso de família e a exigência de
evidência comportamental para TTPs.

### 6.4 GenAI

Documentar:

- Provedor e modelo.
- Structured output.
- Prompt de sistema.
- Proteção contra instruções em dados externos.
- Grounding.
- Fallback.
- Consumo de tokens.

### 6.5 Persistência

Descrever o SQLite como fonte principal e o CSV como histórico resumido.

### 6.6 Relatório

Demonstrar como o relatório diferencia infraestrutura relacionada, atividade de
rede observada, candidato a C2 e C2 confirmado.

## 7. Testes

Registrar o comando:

```powershell
python -m pytest -q
```

Evidências mínimas:

- Quantidade de testes aprovados.
- Testes dos clientes.
- Testes de normalização.
- Testes determinísticos.
- Testes do agente.
- Testes do relatório.
- Testes da API.
- Teste mockado da GenAI.
- Uma execução real controlada.

## 8. Resultados

Preencher com o scan real:

| Campo | Resultado |
|---|---|
| Hash | `<preencher>` |
| Scan ID | `<preencher>` |
| Status | `<preencher>` |
| Veredito | `<preencher>` |
| Confiança | `<preencher>` |
| Família principal | `<preencher>` |
| TTPs | `<preencher>` |
| Observáveis | `<preencher>` |
| Provider GenAI | `<preencher>` |
| Modelo | `<preencher>` |
| Tokens | `<preencher>` |

Anexar capturas do frontend, Swagger e relatório HTML sem expor chaves.

## 9. Decisões técnicas

Registrar as justificativas para:

- FastAPI.
- Pydantic.
- LangGraph.
- SQLite.
- Análise determinística antes da GenAI.
- Relatório sem nova chamada ao modelo.
- Grounding obrigatório.
- Docker com usuário sem privilégio.

## 10. Segurança da solução

Descrever validação de entrada, proteção contra prompt injection, XSS, CSV
Formula Injection, gestão de segredos, timeout, fallback e isolamento do
container.

## 11. Limitações

- Dependência de fontes externas.
- Limites e planos das APIs.
- Ausência de sandbox própria.
- Possibilidade de classificações divergentes.
- Atribuição de família como hipótese.
- Necessidade de validação humana.

## 12. Próximas evoluções

- Autenticação e RBAC.
- Cache com TTL.
- Fila assíncrona para análises longas.
- PostgreSQL.
- Integração com MISP ou OpenCTI.
- STIX 2.1 e TAXII.
- Enriquecimento de IP e domínio.
- Regras Sigma, YARA-L e KQL revisadas por analistas.
- Métricas e tracing do LangGraph.
- CI/CD e análise de dependências.

## 13. Conclusão

Resumir os ganhos de tempo, padronização, rastreabilidade e apoio ao processo
de decisão, deixando claro que a GenAI complementa a análise determinística e
não substitui a validação do analista.
