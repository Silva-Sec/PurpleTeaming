# Custom Advanced Rules — Detecções KQL 🎯

> Regras de detecção customizadas (KQL) para **Microsoft Sentinel** e **Microsoft Defender XDR Advanced Hunting**, desenvolvidas e testadas em operações reais de Threat Hunting.

## 📂 Detecções disponíveis

| Regra | Técnica MITRE ATT&CK | Fonte de dados | Descrição |
|---|---|---|---|
| [BruteForce](BruteForce/) | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | `EntraIdSignInEvents` + `IdentityInfo` | Detecta falhas de MFA e bloqueios de Acesso Condicional originados de IPs estrangeiros, focando em **contas habilitadas** — forte indicativo de password spray ou uso de credenciais vazadas. |

---

## 🧩 Estrutura

```
CustomAdvancedRules/
└── BruteForce/
    ├── README.md              # Descrição, caso de uso, pré-requisitos e falsos positivos
    └── PasswordSprayRule.kql  # Query KQL comentada linha a linha
```

Cada detecção segue o mesmo padrão de documentação:

1. **Descrição** — o que a regra monitora e por quê
2. **Caso de uso** — quando ela gera valor (mitigação de risco / hunting)
3. **Pré-requisitos** — tabelas e licenciamento necessários
4. **Configuração** — variáveis a ajustar (whitelist de IPs, país de baseline)
5. **Falsos positivos conhecidos** — o que revisar antes de colocar em produção

---

## ⚙️ Como usar

1. Abra a pasta da detecção e leia o `README.md` específico.
2. Ajuste as variáveis de ambiente no início da query (ex: `IpsValidos`, código do país).
3. Cole no **Advanced Hunting** (Defender XDR) para testar em modo interativo.
4. Valide os resultados por alguns dias, avaliando falsos positivos.
5. Promova a **Custom Detection Rule** com agendamento e severidade adequados ao seu ambiente.

> ⚠️ Todas as queries contêm placeholders (CIDRs, códigos de país) que **precisam** ser ajustados ao seu ambiente antes de uso em produção.

---

## 🗺️ Roadmap

- [ ] Detecção de impossible travel (Entra ID)
- [ ] Detecção de consent phishing (OAuth app grants suspeitos)
- [ ] Mapeamento de cobertura por técnica ATT&CK no README raiz

Contribuições e relatos de tuning são bem-vindos via [Issues](../../../../issues).

---

## Licença

[MIT](../../../../LICENSE) © 2026 Jonathan Silva
