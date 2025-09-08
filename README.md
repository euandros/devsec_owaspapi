# Estudo Sobre Desenvolvimento Seguro de APIs
O **OWASP API Security Risks** é um projeto da OWASP (Open Web Application Security Project) que visa identificar e descrever os principais riscos de segurança associados ao uso de APIs. Esses riscos representam ameaças potenciais às APIs e podem comprometer a integridade, confidencialidade e disponibilidade dos dados. O que se segue é a materialização do estudo que tenho feito sobre o tema e, por ser um estudo, não se trata de algo definitivo, mas sim em desenvolvimento contínuo.

**Principais Ameaças**:

1. **Autorização de nível de objeto quebrada**: Permite que usuários não autenticados acessem e alterem dados críticos. Representa aproximadamente 40% de todas as violações de segurança da API.
2. **Autenticação quebrada**: Permite que intrusos obtenham acesso não autorizado a aplicativos usando métodos como tokens roubados ou ataques de força bruta.
3. **Autorização de propriedade de objeto quebrada**: Envolve acesso não autorizado a dados confidenciais por meio de exposição de dados excessiva ou atribuição em massa.
4. **Consumo de recursos não restrito**: APIs que não seguem restrições no uso de recursos, tornando-as alvo para ataques de força bruta.
5. **Autorização de nível de função quebrada (BFLA)**: Usuários não autenticados podem executar funções da API como adicionar, atualizar ou excluir registros.
6. **Acesso irrestrito a fluxos de negócios sensíveis**: API revela processos de negócios sem considerar o potencial de dano se a função for automatizada em excesso.
7. **Falsificação de solicitação do lado do servidor (SSRF)**: Ocorre quando uma API aceita uma URL controlada pelo usuário e o servidor back-end a processa.
8. **Configuração de segurança incorreta**: Abrange uma ampla gama de erros de configuração que prejudicam a segurança da API.
9. **Gerenciamento de Inventário Inadequado**: Surge de um inventário desatualizado ou incompleto, resultando em pontos cegos não identificados.
10. **Consumo Inseguro de APIs**: Decorrente da utilização incorreta de APIs por parte dos clientes de API.

Para mitigar essa ameaça, é fundamental revisar e configurar adequadamente todas as partes do sistema, seguir as melhores práticas de configuração e utilizar ferramentas de análise estática para identificar configurações inseguras em código-fonte.

**OWASP Secure Coding Practices (SCP)**: O OWASP Secure Coding Practices (SCP) é um guia de referência rápida para boas práticas de codificação segura. Ele foi desenvolvido pela OWASP Foundation e é voltado para desenvolvedores de software em geral, independentemente da tecnologia específica que estão usando.

O guia apresenta práticas de codificação que podem ser traduzidas em requisitos de codificação sem a necessidade de o desenvolvedor possuir uma compreensão aprofundada das vulnerabilidades e exploits de segurança.

**Práticas Incluem**:

- **Validação de entrada**: Garantir que os dados fornecidos pelo usuário sejam seguros e confiáveis.
- **Codificação de saída**: Proteger dados enviados ao usuário com técnicas como codificação HTML e URL.
- **Gerenciamento de autenticação e senha**: Armazenamento seguro de senhas e uso de funções hash.
- **Gerenciamento de sessão**: Proteção de sessões com cookies seguros e tokens CSRF.
- **Controle de acesso**: Limitar acesso às informações necessárias para cada usuário.
- **Práticas criptográficas**: Uso de criptografia simétrica, assimétrica e hashing.
- **Tratamento e registro de erros**: Registro adequado de erros e tratamento via exceções.
- **Proteção de dados**: Criptografia durante armazenamento, transmissão e processamento.
- **Segurança da comunicação**: Uso de SSL/TLS e autenticação mútua.
- **Configuração do sistema**: Configurações padrão seguras e personalizadas.
- **Segurança do banco de dados**: Permissões, criptografia e monitoramento de atividades.
- **Gerenciamento de arquivos**: Criptografia e transmissão segura de arquivos.

#### **Implementação Segura**

##### **Privacy by Design**

_Privacy by Design_ assegura que a privacidade seja considerada desde o início do ciclo de vida do desenvolvimento da API.

**Princípios do Privacy by Design**

1. **Coleta Mínima de Dados**: Coletar apenas dados estritamente necessários.
2. **Consentimento Explícito**: Requerer permissão clara do usuário.
3. **Segurança de Ponta a Ponta**: Proteger dados em todas as fases.
4. **Retenção Limitada**: Definir políticas claras de expiração de dados.

```python
# Exemplo de API com Privacy by Design
@app.route('/api/user/data', methods=['POST'])
def collect_user_data():
    """Endpoint que implementa Privacy by Design"""
    data = request.json
    user_id = data.get('user_id')
    
    # Verificar consentimento antes de processar
    if not api.check_consent(user_id, 'data_processing'):
        return jsonify({'error': 'Consent required'}), 403
    
    # Minimização de dados - coletar apenas o necessário
    required_fields = ['name', 'email']
    filtered_data = {k: v for k, v in data.items() if k in required_fields}
    
    # Implementar retenção de dados
    expiry_date = datetime.now() + api.data_retention_policy
    return jsonify({
        'status': 'success',
        'data_expiry': expiry_date.isoformat()
    })
```

##### **Security by Design**

_Security by Design_ garante que considerações de segurança sejam integradas em todas as decisões arquiteturais de APIs. Esta abordagem previne vulnerabilidades através de design seguro ao invés de depender de controles adicionados posteriormente.

**Princípios de Security by Design para APIs**

1. **Autenticação Forte**: Implementar múltiplos fatores quando apropriado.
2. **Autorização Granular**: Controle de acesso baseado em recursos específicos.
3. **Validação Rigorosa**: Validar todas as entradas no servidor.
4. **Criptografia Ubíqua**: Proteger dados em trânsito e em repouso.
5. **Logging Abrangente**: Registrar todas as atividades para auditoria.
6. **Rate Limiting**: Prevenir abuso e ataques de negação de serviço.
7. **Versionamento Seguro**: Manter compatibilidade sem comprometer segurança.

```python
# Exemplo de API com Security by Design
@app.route('/api/secure-endpoint', methods=['GET'])
@require_auth
@require_permission('read_data')
def secure_endpoint():
    """Endpoint seguro com autenticação e autorização"""
    # Verificar rate limiting
    if not api_framework.check_rate_limit(g.current_user['user_id']):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # Implementar lógica de negócio
    return jsonify({'data': 'secure_data'})
```

##### **OWASP API Security Top 10**

A implementação de controles baseados no OWASP API Security Top 10 garante proteção contra as vulnerabilidades mais comuns em APIs. Cada categoria requer controles específicos e validação contínua.

---

### **Estudo de Caso Prático: Análise de Vulnerabilidades na API ToDoList**

#### **Análise de Vulnerabilidades da API ToDoList (OWASP API Security Top 10 2023)**

Este documento apresenta uma análise de segurança da aplicação "API ToDoList", com base no código-fonte fornecido (main.py, requirements.txt, Dockerfile). As vulnerabilidades identificadas são mapeadas para a lista OWASP API Security Top 10 de 2023.

---

#### **API1:2023 - Broken Object Level Authorization (BOLA)**

**Análise:** A API permite que qualquer usuário modifique ou exclua tarefas (Tasks) sem verificar se o solicitante é o proprietário do objeto. Um atacante pode enumerar IDs de tarefas (tarefa_id) e, assim, visualizar, alterar ou apagar dados de outros usuários. A mesma falha existe para a manipulação de usuários (PUT /usuarios/{usuario_id} e DELETE /usuarios/{usuario_id}), onde não há verificação se o usuário que realiza a ação tem permissão para tal.

**Snippet de Código Vulnerável:** O endpoint excluir_tarefa localiza a tarefa apenas pelo seu id, sem considerar o user_id do solicitante.

```python
# main.py

@app.delete("/tarefas/{tarefa_id}", status_code=status.HTTP_204_NO_CONTENT)
def excluir_tarefa(tarefa_id: int, db: Session = Depends(get_db)):
    db_tarefa = db.query(Task).filter(Task.id == tarefa_id).first()

    if db_tarefa is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarefa não encontrada")

    db.delete(db_tarefa)
    db.commit()
    return None
```

**Proposta de Correção:** A correção exige a implementação de um sistema de autenticação para identificar o usuário atual. Em seguida, a consulta ao banco de dados deve ser modificada para incluir o id do usuário logado, garantindo que ele só possa apagar as suas próprias tarefas.

_Nota: As funções_ _get_current_user_ _e oauth2_scheme são representações de um mecanismo de autenticação (ex: OAuth2 com JWT) que precisa ser implementado._

```python
from fastapi.security import OAuth2PasswordBearer

# Placeholder para o esquema de autenticação
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Placeholder para a função que obtém o usuário atual a partir do token
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Em um cenário real, aqui você decodificaria o token JWT e buscaria o usuário no DB
    # Para este exemplo, vamos assumir um usuário fixo.
    user = db.query(User).filter(User.id == 1).first() # Simulação: usuário com ID 1
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    return user

# ...

@app.delete("/tarefas/{tarefa_id}", status_code=status.HTTP_204_NO_CONTENT)
def excluir_tarefa(
    tarefa_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # A consulta agora verifica tanto o ID da tarefa quanto o ID do usuário proprietário
    db_tarefa = db.query(Task).filter(Task.id == tarefa_id, Task.user_id == current_user.id).first()

    if db_tarefa is None:
        # Retorna 404 para não vazar a informação se a tarefa existe mas pertence a outro usuário
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarefa não encontrada")

    db.delete(db_tarefa)
    db.commit()
    return None
```

**Explicação da Correção:** A nova implementação introduz current_user: User = Depends (get_current_user), que garante que o endpoint só pode ser acessado por um usuário autenticado. A consulta db.query(Task).filter(Task.id == tarefa_id, Task.user_id == current_user.id) agora impõe a autorização a nível de objeto, assegurando que um usuário só pode excluir uma tarefa que lhe pertence (Task.user_id == current_user.id).

---

#### **API2:2023 - Broken Authentication**

**Análise:** A API não possui **nenhum mecanismo de autenticação**. Todos os endpoints, incluindo aqueles que criam, modificam e excluem dados, são públicos e podem ser acessados por qualquer pessoa sem necessidade de fornecer credenciais. Isso permite que qualquer atacante anônimo execute todas as operações da API livremente.

**Snippet de Código Vulnerável:** O endpoint de criação de tarefas não requer autenticação, permitindo que qualquer um crie tarefas para qualquer user_id especificado no corpo da requisição.

```python
# main.py

@app.post("/tarefas", response_model=TaskResponse)
def criar_tarefa(tarefa: TaskRequest, db: Session = Depends(get_db)):
    db_tarefa = Task(**tarefa.model_dump())
    db.add(db_tarefa)
    db.commit()
    db.refresh(db_tarefa)
    return db_tarefa
```

**Proposta de Correção:** Todos os endpoints que acessam ou modificam dados sensíveis devem ser protegidos, exigindo um token de autenticação válido. O user_id da tarefa deve ser extraído do token do usuário autenticado, e não do corpo da requisição, para garantir que um usuário só possa criar tarefas para si mesmo.

```python
# (Utilizando as mesmas funções 'oauth2_scheme' e 'get_current_user' da correção anterior)

@app.post("/tarefas", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def criar_tarefa(
    tarefa: TaskRequest, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # O user_id é obtido do usuário autenticado, não do corpo da requisição
    # O model_dump() da tarefa é combinado com o ID do usuário atual
    tarefa_data = tarefa.model_dump()
    tarefa_data['user_id'] = current_user.id
    
    db_tarefa = Task(**tarefa_data)
    db.add(db_tarefa)
    db.commit()
    db.refresh(db_tarefa)
    return db_tarefa
```

**Explicação da Correção:** Ao adicionar current_user: User = Depends(get_current_user), o endpoint passa a exigir autenticação. A lógica é alterada para ignorar qualquer user_id que possa vir no corpo da requisição (tarefa: TaskRequest) e, em vez disso, atribuir o id do usuário autenticado (current_user.id) à nova tarefa. Isso previne que um usuário crie recursos em nome de outro.

---

#### **API3:2023 - Broken Object Property Level Authorization (Mass Assignment)**

**Análise:** O endpoint de atualização de tarefas (PUT /tarefas/{tarefa_id}) utiliza um loop genérico (for key, value in tarefa.model_dump().items()) para atualizar todos os campos enviados na requisição. Isso representa uma vulnerabilidade de _Mass Assignment_. Um atacante poderia incluir no corpo da requisição o campo user_id e alterar o proprietário de uma tarefa, transferindo-a para sua própria conta, o que constitui uma falha de autorização a nível de propriedade.

**Snippet de Código Vulnerável:**

```python
# main.py

@app.put("/tarefas/{tarefa_id}", response_model=TaskResponse)
def atualizar_tarefa(tarefa_id: int, tarefa: TaskRequest, db: Session = Depends(get_db)):
    # ... (código de busca da tarefa omitido)
    
    if db_tarefa is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarefa não encontrada")

    # Atualiza TODOS os campos da tarefa com base no payload
    for key, value in tarefa.model_dump().items():
        setattr(db_tarefa, key, value)

    db.commit()
    db.refresh(db_tarefa)
    return db_tarefa
```

**Proposta de Correção:** Em vez de usar um loop genérico, a correção atribui explicitamente apenas as propriedades que o usuário tem permissão para modificar (title, description, status). Propriedades sensíveis como user_id não devem ser atualizáveis por este método.

```python
# (Assumindo que a proteção de autenticação e BOLA já foi aplicada)
from schemas import TaskUpdateRequest # Um schema específico para atualização

# schemas.py (sugestão)
# class TaskUpdateRequest(BaseModel):
#     title: Optional[str] = None
#     description: Optional[str] = None
#     status: Optional[str] = None

@app.put("/tarefas/{tarefa_id}", response_model=TaskResponse)
def atualizar_tarefa(
    tarefa_id: int, 
    tarefa_update: TaskUpdateRequest, # Usar um schema específico para update
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_tarefa = db.query(Task).filter(Task.id == tarefa_id, Task.user_id == current_user.id).first()

    if db_tarefa is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarefa não encontrada")

    # Atribuição explícita apenas dos campos permitidos
    update_data = tarefa_update.model_dump(exclude_unset=True)
    if "title" in update_data:
        db_tarefa.title = update_data["title"]
    if "description" in update_data:
        db_tarefa.description = update_data["description"]
    if "status" in update_data:
        db_tarefa.status = update_data["status"]
    
    # O campo 'user_id' nunca é modificado a partir da entrada do usuário.

    db.commit()
    db.refresh(db_tarefa)
    return db_tarefa
```

**Explicação da Correção:** A nova lógica substitui o setattr em loop por atribuições explícitas e controladas. Isso garante que apenas os campos title, description e status possam ser modificados. A utilização de um Pydantic model específico para atualização (TaskUpdateRequest), que não contém o campo user_id, adiciona uma camada extra de segurança a nível de validação de entrada.

---

#### **API4:2023 - Unrestricted Resource Consumption**

**Análise:** O endpoint GET /tarefas busca e retorna **todas** as tarefas do banco de dados com a consulta db.query(Task).all(). Em um sistema com um grande volume de dados, essa operação pode consumir uma quantidade excessiva de memória e CPU do servidor, levando a uma condição de Negação de Serviço (DoS) e tornando a API lenta ou indisponível para todos os usuários. Não há implementação de paginação.

**Snippet de Código Vulnerável:**

```python
# main.py

@app.get("/tarefas", response_model=List[TaskResponse])
def listar_tarefas(db: Session = Depends(get_db)):
    tarefas = db.query(Task).all()
    return tarefas
```

**Proposta de Correção:** Implementar paginação no endpoint, permitindo que os clientes solicitem os dados em "pedaços" (páginas). Parâmetros como skip (pular) e limit (limitar) são adicionados à função, com valores padrão e máximos para evitar abusos.

```python
from fastapi import Query

# ...

@app.get("/tarefas", response_model=List[TaskResponse])
def listar_tarefas(
    db: Session = Depends(get_db), 
    skip: int = 0, 
    limit: int = Query(default=10, le=100) # Padrão 10, máximo 100
):
    tarefas = db.query(Task).offset(skip).limit(limit).all()
    return tarefas
```

**Explicação da Correção:** A função agora aceita os parâmetros skip e limit. skip define o ponto de partida da busca (útil para navegar entre páginas), e limit controla o número máximo de registros retornados. A função Query do FastAPI é usada para definir um valor padrão (default=10) e um limite máximo (le=100, _less than or equal to_), impedindo que um cliente solicite um número excessivo de recursos de uma só vez. A consulta ao banco de dados agora utiliza .offset(skip).limit(limit).

---

#### **API5:2023 - Broken Function Level Authorization (BFLA)**

**Análise:** A API expõe funcionalidades que deveriam ser restritas a um perfil de administrador, como a exclusão de usuários (DELETE /usuarios/{usuario_id}), para qualquer usuário anônimo. Não há distinção entre usuários comuns e administradores, violando a autorização a nível de função. Um usuário comum (ou um atacante) não deveria ter permissão para executar ações administrativas.

**Snippet de Código Vulnerável:**

```python
# main.py

@app.delete("/usuarios/{usuario_id}", status_code=status.HTTP_204_NO_CONTENT)
def excluir_usuario(usuario_id: int, db: Session = Depends(get_db)):
    db_usuario = db.query(User).filter(User.id == usuario_id).first()

    if db_usuario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")

    db.delete(db_usuario)
    db.commit()
    return None
```

**Proposta de Correção:** A correção envolve a introdução de um sistema de papéis (roles) para os usuários (ex: um campo is_admin no modelo User). O endpoint deve, então, verificar se o current_user autenticado possui o papel de administrador antes de permitir a execução da função.

```python
# (Assumindo que o modelo 'User' tem um campo booleano 'is_admin')
# (Utilizando a função 'get_current_user' das correções anteriores)

def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Acesso negado. Requer privilégios de administrador."
        )

@app.delete("/usuarios/{usuario_id}", status_code=status.HTTP_204_NO_CONTENT)
def excluir_usuario(
    usuario_id: int, 
    db: Session = Depends(get_db), 
    admin_user: None = Depends(require_admin) # Injeta a dependência de verificação de admin
):
    # A lógica de exclusão só é executada se 'require_admin' não lançar uma exceção
    db_usuario = db.query(User).filter(User.id == usuario_id).first()

    if db_usuario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")

    db.delete(db_usuario)
    db.commit()
    return None
```

**Explicação da Correção:** Foi criada uma nova função de dependência, require_admin, que verifica se o usuário autenticado tem a flag is_admin. Essa dependência é injetada no endpoint excluir_usuario. Se o usuário não for um administrador, a função require_admin lançará uma exceção HTTP 403 Forbidden, e o código de exclusão do usuário nunca será executado. Isso garante que apenas usuários com o nível de função adequado possam acessar este endpoint.

---

#### **API8:2023 - Security Misconfiguration**

**Análise:** A aplicação apresenta múltiplas falhas de configuração de segurança:

1. **Exposição de Informações em Erros:** O endpoint healthcheck pode vazar detalhes internos do banco de dados em caso de falha, auxiliando um atacante no reconhecimento do sistema.
2. **Execução como Root no Contêiner:** O Dockerfile não especifica um usuário não-privilegiado, fazendo com que a aplicação rode como root dentro do contêiner. Isso viola o princípio do menor privilégio e aumenta o impacto de uma possível vulnerabilidade de execução remota de código.
3. **Dependências Desatualizadas:** O arquivo requirements.txt especifica versões antigas de bibliotecas, como sqlalchemy==1.4.41 (a versão 2.x já é estável há tempos) e uvicorn==0.17.6. Versões desatualizadas podem conter vulnerabilidades conhecidas (CVEs) que já foram corrigidas em versões mais recentes.

**Snippet de Código Vulnerável:** Exposição de detalhes de erro no endpoint healthcheck.

```python
# main.py

@app.get("/healthcheck")
def healthcheck(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1")) # Use text() aqui
        return {"status": "ok"}
    except Exception as e:
        # Vaza a mensagem de exceção 'e' para o cliente
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e}")
```

**Proposta de Correção:** A correção envolve tratar a exceção de forma segura, registrando o erro detalhado em logs no servidor para depuração e retornando uma mensagem genérica para o cliente.

```python
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ...

@app.get("/healthcheck")
def healthcheck(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as e:
        # Registra o erro detalhado no log do servidor
        logger.error(f"Healthcheck falhou: {e}", exc_info=True)
        # Retorna uma mensagem genérica para o cliente
        raise HTTPException(status_code=503, detail="Serviço indisponível")
```

**Explicação da Correção:** Em vez de expor a exceção e diretamente na resposta HTTP, a nova versão registra o erro completo no lado do servidor usando o módulo logging. Para o cliente, é retornada uma mensagem genérica ("Serviço indisponível") com um status code apropriado (503 Service Unavailable), escondendo detalhes da infraestrutura interna. As outras más configurações (contêiner e dependências) devem ser corrigidas no Dockerfile e no requirements.txt, respectivamente.

---

#### **Categorias do OWASP API Top 10 Não Aplicáveis**

- **API6:2023 - Unrestricted Access to Sensitive Business Flows:** A aplicação é um CRUD simples e não possui fluxos de negócio complexos (ex: processo de compra, transferência de fundos) que poderiam ser abusados.
- **API7:2023 - Server Side Request Forgery (SSRF):** O código da API não faz requisições a URLs externas fornecidas pelo usuário. Sua única comunicação externa é com o banco de dados, cujo endereço não é controlado pelo usuário.
- **API9:2023 - Improper Inventory Management:** Esta vulnerabilidade está relacionada à governança e à falta de documentação ou desativação de APIs antigas ("shadow APIs"). A análise estática de um único código-fonte não permite identificar falhas de gerenciamento de inventário no ambiente de produção.
- **API10:2023 - Unsafe Consumption of APIs:** Esta categoria se refere a como a aplicação consome APIs de terceiros de forma insegura. A API ToDoList atua apenas como um provedor de API e não consome nenhum serviço externo.

Para aplicação destes conceitos irei construir uma outra aplicação que nos compreender o risco e como corrigir a vulnerabilidade mitigando os erros. É um dever de casa que preciso conculir.

