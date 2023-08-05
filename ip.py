from iputils import *

import ipaddress

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama

            ttl -= 1 # Decrementa o TTL antes de encaminhar o datagrama

            if ttl <= 0:
                return # Descarta o datagrama se o TTL zerar

            # Corrige o checksum do cabeçalho
            header = struct.pack('!BBHHHBBH4s4s', (4 << 4) | 5, dscp << 2 | ecn, len(datagrama), identification, (flags << 13) | frag_offset, ttl, proto, 0, str2addr(src_addr), str2addr(dst_addr))
            checksum = calc_checksum(header)
            header = struct.pack('!BBHHHBBH4s4s', (4 << 4) | 5, dscp << 2 | ecn, len(datagrama), identification, (flags << 13) | frag_offset, ttl, proto, checksum, str2addr(src_addr), str2addr(dst_addr))

            datagrama = header + payload

            # Encaminha o datagrama para o próximo roteador
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        """
        Use a tabela de encaminhamento para determinar o próximo salto
        (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        Retorne o next_hop para o dest_addr fornecido.
        """
        dest_ip = ipaddress.IPv4Address(dest_addr)
        matching_routes = []

        for network, next_hop in self.tabela:
            if dest_ip in network:
                matching_routes.append((network, next_hop))

        if not matching_routes:
            return None

        # Função para comparar rotas com base no prefixo (para usar com sort)
        def compare_routes(route):
            return route[0].prefixlen

        # Ordena as rotas coincidentes com base no comprimento do prefixo em ordem decrescente
        matching_routes.sort(key=compare_routes, reverse=True)

        # Retorna o próximo salto da rota com o prefixo mais longo
        return str(matching_routes[0][1])

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = []
        for cidr, next_hop in tabela:
            self.tabela.append((ipaddress.IPv4Network(cidr), ipaddress.IPv4Address(next_hop)))

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        protocolo = IPPROTO_TCP

        total_length = 20 + len(segmento)  # Comprimento total do datagrama IP (cabeçalho + payload)

        # Cabeçalho IP com versão IPv4 e IHL de 5 (20 bytes)
        ip_header = struct.pack('!BBHHHBBH4s4s', (4 << 4) | 5, 0, total_length, 10, 0, 64, protocolo, 0, str2addr(self.meu_endereco), str2addr(dest_addr))

        # Calcular o checksum
        checksum = calc_checksum(ip_header)

        # Inserir o checksum no cabeçalho
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]

        # Montar o datagrama completo (cabeçalho + payload)
        datagrama = ip_header + segmento

        self.enlace.enviar(datagrama, next_hop)
