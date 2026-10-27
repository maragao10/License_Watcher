# License Watcher

App local com tela gráfica para monitorar validade de licenças de produtos com API REST e avisar no Webex.

## Rodar
```bash
pip install -r requirements.txt
python app.py        # abre em http://localhost:5000
```
Variáveis opcionais: `LW_HOST` (padrão 127.0.0.1), `LW_PORT`, `LW_DATA` (pasta do banco, padrão `data/`), `LW_SECRET` (opcional).

## Acesso
O app **não tem login**: quem alcança a porta vê a tela e as credenciais cadastradas. Use só em rede interna fechada
(ou coloque um proxy com autenticação na frente).

## Como usar
1. **Produtos > Adicionar produto**: escolha o tipo em **Autenticação** (Bearer, basic, header, login com token, vCenter, Manual), preencha URL e credenciais e configure as consultas.
2. Cada produto tem **uma ou mais consultas de licença** (um GET cada). Um produto com várias licenças em endpoints diferentes
   (ex: Splunk Enterprise e ITSI) ganha uma consulta por endpoint. Dá para adicionar e remover consultas na própria tela.
3. Clique em **Testar** para ver quantas licenças foram lidas ou qual foi o erro.
4. **Alertas Webex**: informe webhook (ou bot + sala), dias de antecedência (30), dia e hora do aviso semanal. Use "Salvar e enviar teste".
5. O **Dashboard** mostra expiradas, vencendo e em dia. "Atualizar e alertar" dispara a verificação na hora.

## Como o aviso funciona
Toda semana (dia/hora configurados) o app consulta todos os produtos ativos e manda ao Webex tudo que expira em até N dias ou já expirou.
Como a regra roda a cada semana, o aviso se repete até a licença ser renovada. Produtos que falham aparecem no alerta como erro.

## Campos de uma consulta
- **Caminho:** parte do GET depois da URL base (pode ter query string).
- **Lista no JSON:** caminho até a lista de licenças, ex. `entry` ou `response.license_details` (vazio se a resposta já é a lista).
- **Campo do nome / de expiração:** caminhos dentro de cada item, ex. `content.label`, `content.expiration_time`.
  Datas aceitas: ISO, dd/mm/aaaa, `Apr 3, 2026 UTC` (formato Meraki), epoch em segundos ou milissegundos.
- **Nome fixo:** se a resposta não tem um campo de nome, escreva `=` antes do texto no campo do nome (ex: `=Meraki co-termination`).

## vCenter
Autenticação **vCenter / vSphere**: lê as licenças pela API do vSphere (LicenseManager, via pyvmomi) com usuário e senha somente leitura. Licenças perpétuas ("Never") não têm data e não aparecem; a de avaliação (incluindo hosts em Evaluation Mode) e as por assinatura aparecem com a validade.

## Meraki
Organizações em co-termination: consulta `GET /organizations/<id>/licenses/overview`, lista vazia, nome `=Meraki co-termination`, expiração `expirationDate`.
O endpoint `/organizations/<id>/licenses` só funciona em organizações com licenciamento por dispositivo (nas demais retorna 400).

## Produtos sem API (licença manual)
Para produtos sem API de licença (ex: ThousandEyes, cuja API não expõe a data de vencimento do contrato): **Produtos > Adicionar produto >
autenticação "Manual"**. Informe o nome de cada licença e a data de vencimento; elas entram no Dashboard e no alerta do Webex como as outras.
Quando renovar, edite a data. Produtos desativados (desmarcar "Ativo") não aparecem no Dashboard nem nos alertas.

## Atenção
- Não há modelos prontos: configure as consultas de cada produto na tela (caminho, lista, campos de nome e validade) conforme o Swagger/doc dele.
  Exemplo Splunk: `/services/licenser/licenses?output_mode=json&count=0`, lista `entry`, nome `content.label`, expiração `content.expiration_time`.
- Segredos ficam criptografados no SQLite com a chave `data/secret.key`. Proteja essa pasta e não versione.
- O app precisa rodar onde alcança os produtos (VM interna para ISE e Catalyst Center).
- Use contas de API somente leitura.
