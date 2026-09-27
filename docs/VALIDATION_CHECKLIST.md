# Checklist final de validação

## Ambiente

- [ ] `.venv` está ativo.
- [ ] Dependências de `requirements-dev.txt` foram instaladas.
- [ ] `.env` existe e não está versionado.
- [ ] Chaves reais não aparecem em capturas ou documentação.

## Qualidade

- [ ] `python -m pytest -q` retorna 46 testes aprovados ou mais.
- [ ] VS Code/Pylance não apresenta erros.
- [ ] A aplicação inicia sem traceback.

## API

- [ ] `GET /api/v1/health` retorna 200.
- [ ] `POST /api/v1/triage` retorna 201.
- [ ] VirusTotal e MalwareBazaar aparecem na lista de providers.
- [ ] `GET /api/v1/scans` retorna o scan criado.
- [ ] `GET /api/v1/scans/{scan_id}` retorna o mesmo resultado.
- [ ] Exportação CSV retorna 200.
- [ ] Busca de observáveis retorna resultados esperados.
- [ ] Endpoint de estatísticas retorna totais coerentes.

## GenAI

- [ ] Mock registra `attempted=true` e tokens sintéticos.
- [ ] `use_genai=false` não chama o modelo.
- [ ] Falha do modelo ativa fallback determinístico.
- [ ] Execução real registra provider, modelo e tokens.
- [ ] `source_errors` fica vazio quando a chamada funciona.
- [ ] Alegações sem evidência são removidas no grounding.

## Relatório

- [ ] JSON contém cinco PIRs.
- [ ] Família possui `supporting_evidence_ids` válidos.
- [ ] TTP possui evidência comportamental válida.
- [ ] C2 candidato não aparece como confirmado.
- [ ] HTML abre corretamente.
- [ ] Valores não confiáveis são escapados.
- [ ] Impressão ou exportação do navegador para PDF funciona.

## Frontend

- [ ] Formulário aceita o hash.
- [ ] É possível selecionar os dois provedores.
- [ ] É possível habilitar e desabilitar GenAI.
- [ ] Resultado atual é exibido.
- [ ] Links de relatório e CSV funcionam.
- [ ] Histórico é exibido.
- [ ] Busca de observável funciona.

## Docker

- [ ] `docker compose up --build -d` conclui sem erro.
- [ ] Container fica `healthy`.
- [ ] Porta 8000 responde.
- [ ] Aplicação executa como usuário sem privilégio.
- [ ] SQLite e CSV persistem após reiniciar o container.

## Evidências para o case

- [ ] Arquitetura.
- [ ] Swagger.
- [ ] Frontend.
- [ ] Resultado do pytest.
- [ ] Resposta de uma triagem.
- [ ] `analysis_execution` com tokens.
- [ ] Histórico SQLite/API.
- [ ] Relatório HTML.
- [ ] Docker saudável.
- [ ] Conclusão e limitações.
