package main

import (
    "fmt"
    "net"
    "flag"
    "encoding/gob"
    "math/rand"
    "crypto/sha256"
    "crypto/hmac"
    "math/big"
    "strconv"
    "time"
)

//struct usado para recebimento das mensagens
type Mensagem struct {
    Mnome, Mmsg string
    Mhmac []byte
    Mnonce int
}

//struct usado para envio recebimento das infos do diffiehellman
type Diffie struct {
    Dinteiro int64
    Dprimo int64
    Dchave_publica int64
    Dnonce_inicial int
    Dnonce_final int
}

//funcao que checa o hmac recebido na mensagem do client
func checaHmac (str string, nome string, nonce int, hmacRecebido []byte, chave_secreta_server string) bool {
    h := sha256.New()
    concatenado := str + nome + strconv.Itoa(nonce)
    h.Write([]byte(concatenado))
    hash := h.Sum(nil)
    m := hmac.New(sha256.New, []byte(chave_secreta_server))
    m.Write(hash)
    hmacGerado := m.Sum(nil)
    fmt.Printf("Hmac Gerado: %x\n", hmacGerado)
    return hmac.Equal(hmacRecebido, hmacGerado)
}

//funcao que gera as chaves do diffiehellman
func diffieHellman (inteiro int64, primo int64, chave_publica_client int64) (int64, string) {
    
    //definicao do valor secreto do server
    rand.Seed(time.Now().UnixNano())
    secreto_server := rand.Intn(10000)
    
    //calculo da chave publica do server
    calculo := new(big.Int)
    calculo = calculo.Mod(calculo.Exp(big.NewInt(int64(inteiro)), big.NewInt(int64(secreto_server)), nil), big.NewInt(int64(primo)))
    var chave_publica_server int64 = int64(calculo.Uint64())

    //calculo da chave secreta do server
    calculo = calculo.Mod(calculo.Exp(big.NewInt(int64(chave_publica_client)), big.NewInt(int64(secreto_server)), nil), big.NewInt(int64(primo)))
    chave_secreta_server := int64(calculo.Uint64())

    //retorna a chave publica e secreta ciradas
    return chave_publica_server, strconv.FormatInt(chave_secreta_server, 10)
    
    
}



func main() {
    fmt.Println("Aguardando conexoes...");
    //Recebendo argumentos
    var nome, porta string
    var tam_mensagem, n_mensagens int
    flag.StringVar(&nome, "nome", "Bob", "Nome do cliente")
    flag.StringVar(&porta, "porta", "8080", "Porta do servidor")
    flag.IntVar(&n_mensagens, "n_mensagens", 3, "Numero de mensagens")
    flag.IntVar(&tam_mensagem, "tam_mensagem", 20, "Tamanho da mensagem")
    flag.Parse()

    //abrindo a conexão
    ln, err := net.Listen("tcp", ":"+porta)
    if err != nil {
        fmt.Println("Erro ao abrir a conexao! ", err)
    }
    
    //aceitando conexoes
    conn, err := ln.Accept() // this blocks until connection or error
    if err != nil {
        fmt.Println("Erro ao aceitar a conexao! ", err)
        
    }
    
    //negociacao diffie hellman
    decdif := gob.NewDecoder(conn)
    encdif := gob.NewEncoder(conn)
    dif := &Diffie{}
    decdif.Decode(dif)
    var Chave_publica_server int64
    var chave_secreta_server string
    Chave_publica_server, chave_secreta_server = diffieHellman(dif.Dinteiro, dif.Dprimo, dif.Dchave_publica)
     
    //envio das chaves ao cliente
    resposta := &Diffie{dif.Dinteiro, dif.Dprimo, Chave_publica_server, dif.Dnonce_inicial, dif.Dnonce_final}
    encdif.Encode(resposta)

    //recebimento e checagem das mensagens
    nonce := 0
    for cont := 0; cont <= n_mensagens; cont++ {
        
        //recebimento dados recebidos do client   
        dec := gob.NewDecoder(conn)
        msg := &Mensagem{}
        dec.Decode(msg)
        
        //checagem numero de mensagens
        if cont == n_mensagens && msg.Mmsg != "" {
            conn.Write([]byte(nome + ": Mensagem " + strconv.Itoa(cont) + " recusada (Numero de mensagens excedido)" + "\n"))
            fmt.Printf("Mensagem " + strconv.Itoa(cont) + " recusada: Numero de mensagens excedido \n")
            fmt.Printf("\nEncerrando a conexao... \n")
            continue
        }

        //exibicao dos dados recebidos do client
        if msg.Mmsg != "" {
            fmt.Printf("\nCliente: %s  Contador: %d \n", msg.Mnome, cont);
            fmt.Printf("Mensagem recebida: %s\n", msg.Mmsg)
            fmt.Printf("Hmac Recebido: %x\n", msg.Mhmac)
        } else {
            continue
        }
                   

        //checagem do nonce
        if cont == 0 || nonce == dif.Dnonce_final {
            nonce = dif.Dnonce_inicial
        } else {
            //fmt.Println(msg.Mnonce)
            //fmt.Println(nonce)
            if msg.Mnonce != nonce+1 {
                conn.Write([]byte(nome + ": Mensagem " + strconv.Itoa(cont) + " recusada (Nonce incorreto)" + "\n"))
                fmt.Printf("Mensagem " + strconv.Itoa(cont) + " recusada: Nonce incorreto \n")
                continue
            }
            nonce = msg.Mnonce
        }
        

        //checagem tamanho da mensagem
        if len(msg.Mmsg) != tam_mensagem {
            conn.Write([]byte(nome + ": Mensagem " + strconv.Itoa(cont) + " recusada (Tamanho da mensagem incorreto)" + "\n"))
            fmt.Printf("Mensagem " + strconv.Itoa(cont) + " recusada: Tamanho da mensagem incorreto \n")
            continue
        }

        //checagem do hmac
        check := checaHmac(msg.Mmsg, msg.Mnome, nonce, msg.Mhmac, chave_secreta_server);
        if check == true {
            conn.Write([]byte(nome + ": Mensagem " + strconv.Itoa(cont) + " aceita" + "\n"))
            fmt.Printf("Mensagem aceita \n\n")
        } else {
            conn.Write([]byte(nome + ": Mensagem " + strconv.Itoa(cont) + " recusada (Hmac divergente)" + "\n"))
            fmt.Printf("Mensagem " + strconv.Itoa(cont) + " recusada: Hmac divergente \n\n")
            continue
        }
    }
    //encerramento da conexao
    conn.Close()
}