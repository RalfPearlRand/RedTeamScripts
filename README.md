crypto_bruteforce_v2.py é um Script de decodificação de payload que estou desenvolvendo, estou procurando todos os tipos de criptografias para colocar no script. Para que vocês consigam resolver algum problema, pretendo mudar para C# ou C++ para dar menos trabalho para o processador, ainda vou desenvolver, estou estudando arduino :)  

__________________________________________________________________________________________________________________________________________________________________________________________________________________________


OroochimaruLog é um script de shell desenvolvido para realizar Analises de log, uma interface de linha de comando simples, ele permite que os usuários realizem uma analise de logs, verificando ips, resultado de requisições, portas de serviços, aplicações utilizadas, 
Funcionalidades

O script oferece as seguintes opções:

     [1] Listar Ips
     [2] Qtd de acesso por recurso
     [3] User-Agente utilizados por IP
     [4] Tools utilizadas pelo IP
     [5] Procurar acesso por arquivo
     [6] Primeiro/Último acesso pelo IP

Requisitos

    cat - para trabalhar os dados. 

Instalação

Clone o repositório:

git clone https://github.com/RalfPearlRand/RedTeamScripts.git
cd OroochimaruLog

Dê permissão de execução ao script:

chmod +x OroochimaruLog.sh

Uso

Execute o script com uma das opções disponíveis. Por exemplo:

./OroochimaruLog.sh -a

______________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
JiraiyaRecon é um script de shell desenvolvido para realizar varreduras de portas e serviços em redes. Com uma interface de linha de comando simples, ele permite que os usuários realizem uma variedade de operações de rede, como varredura de portas usando diferentes ferramentas e técnicas.
Funcionalidades

O script oferece as seguintes opções:

    -a: PortScan com Hping3
    -b: Ping Sweep
    -c: Ping Sweep Porta/Serviço
    -d: PortScan em /dev/tcp
    -e: PortScan com NetCat
    -f: Chamar Script Externo
    -g: Extração de Dados
    -h: Localizando Serviços
    -i: Identifica Métodos
    -j: Localizando Servidores Web

Requisitos

    hping3: Para realizar varreduras de portas.
    netcat: Para comunicação de rede.
    nmap: Para identificação de serviços.

Instalação

Clone o repositório:

git clone https://github.com/RalfPearlRand/RedTeamScripts.git
cd Jirayarecon

Dê permissão de execução ao script:

chmod +x Jiraiyarecon.sh

Uso

Execute o script com uma das opções disponíveis. Por exemplo:

./Jiraiyarecon.sh -a


Desenvolvedor Principal: Rafael Lira de Oliveira/0R0CH!S4G3 - https://www.linkedin.com/in/rafael-lira-de-oliveira-734b75224/)

Contribuições Especiais: Carlos Tuma - https://github.com/carlosalbertotuma | https://www.linkedin.com/in/carlos-tuma

0ff3ns!v3 S3cur!ty ®
