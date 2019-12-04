Este arquivo descreve o processo de execução do cliente/servidor implementado em Go

Descrição do programa: o software desenvolvido executa a troca de mensagens entre um cliente e um servidor.
Alguns paramêtros podem ser definidos (vide abaixo) para personalizar a execução, tanto do cliente como do servidor.
O código realiza a sincronização da chave de criptografia entre cliente e o servidor a partir da implementação do 
algoritmo diffiehellman. Desta forma, o cliente gera uma mensagem pseudo-aleartória da qual é gerado um hash juntamente com o 
nome definido e nonce da mensage. Desta hash é gerado o HMAC que utiliza a chave definida via diffiehellman. O cliente então
envia a mensagem ao servidor (esta mensagem contem: string pseudo aleartoria, nome, HMAC e nonce), que realiza o mesmo procedimento 
a fim de validar a HMAC enviada. Além disso o servidor verifica a validade do nonce (evita ataques de mensagens repetidas), o 
numero de mensagens enviadas, o tamanho das mensages enviadas.

Parametros:
-nome           Nome do cliente/servidor
-ip             IP da entidade remota (apenas no cliente)
-porta          Porta de comunicação
-n_mensagens    Número de mensagens a serem enviadas
-tam_mensagem   Tamanho das mensagens a serem enviadas.

Compilação:
go build cliente.go
go build servidor.go

Execução:
O software possui valores pré-definidos para todos os parametros, sendo possível executa-lo de forma direta:
./servidor
./cliente

Assim como os parâmetros podem ser personalizados conforme:
./servidor -nome Bob -porta 8888 -n_mensagens 2000 -tam_mensagem 128
./cliente -nome Alice -ip 127.0.0.1 -porta 8888 -n_mensagens 2000 -tam_mensagem 128
