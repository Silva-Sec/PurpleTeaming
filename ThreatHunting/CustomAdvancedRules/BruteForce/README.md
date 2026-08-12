# Detecta Falhas de MFA e Acesso Condicional de IPs Estrangeiros (Entra ID)

## 📖 Descrição
Esta query de **Custom Detection** monitora logs do Microsoft Entra ID (`EntraIdSignInEvents`) em busca de falhas de autenticação bloqueadas por **MFA (Multi-Factor Authentication)** ou **Políticas de Acesso Condicional**. O foco da regra é identificar possíveis ataques de *password spray*, uso de credenciais vazadas ou tentativas de intrusão, especificamente quando a origem do ataque é de um país estrangeiro não confiável.

A detecção é refinada para ignorar IPs corporativos conhecidos (Whitelist) e acessos originados dentro do país esperado (no caso, o Brasil - `BR`). Além disso, ela garante alta fidelidade ao alertar **apenas** quando o alvo do ataque for uma conta que está atualmente **habilitada** (ativa) no ambiente.

## 🎯 Caso de Uso
* **Mitigação de Riscos:** Detectar quando um atacante já possui a senha correta de um usuário, mas foi barrado por uma camada secundária de segurança (MFA/Conditional Access).
* **Threat Hunting:** Identificar infraestruturas maliciosas (IPs) baseadas no exterior que estão ativamente focando em contas habilitadas da organização.

## ⚙️ Pré-requisitos
* Tabela de logs `EntraIdSignInEvents` ingerida no Microsoft Sentinel ou Advanced Hunting (Microsoft Defender XDR).
* Tabela de logs `IdentityInfo` para mapeamento de status de contas (Habilitada/Desabilitada).

## 🛠️ Como utilizar
1. Edite a variável `IpsValidos` para incluir as sub-redes (CIDR) públicas de saída da sua corporação ou filiais.
2. Se a operação da sua empresa for em outro país principal que não seja o Brasil, altere o valor `"BR"` na condicional do `GeoStatus` para o código ISO do seu país (ex: `"US"`, `"PT"`).

---

## ⚠️ Falsos Positivos Conhecidos
* Usuários em viagens internacionais que estejam tentando acessar suas contas de redes de hotéis ou aeroportos e falhem consecutivamente no desafio do MFA (esquecimento do celular, perda de sinal).
* Serviços de terceiros em nuvem (SaaS hospedados fora do país base) utilizando integrações legadas ou com tokens expirados que acionam bloqueios de Acesso Condicional.
