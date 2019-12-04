package main

import (
    "fmt"
    "os"
    "net"
    "flag"
    "bufio"
    "math/rand"
    "crypto/sha256"
    "crypto/hmac"
    "encoding/gob"
    "math/big"
    "strconv"
    "time"
)

//constante utilizada para gerar string pseudo-aleartoria
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

//struct usado para envio das mensagens
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

//funcao que gera a string pseudo-aleartoria
func geraString (tam int) string {
    str := make([]byte, tam)
    for i := range str {
        str[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(str)
}

//funcao que verifica se o numero gerado e primo (diffiehellman)
func ePrimo(num int) bool {
    for i := 2; i < num; i++ {
        if num%i == 0 {
            
            return false
        }
    }
    return true
}

//funcao que gera numeros inteiros para as variaveis do diffiehellman
//caso receba "true" retorna um numero primo
func geraInt (check bool) int {
    rand.Seed(time.Now().UnixNano())
    inteiro := rand.Intn(10000)
    if check == false {
        return inteiro
    } else {
        for {     
            if ePrimo(inteiro) == false {
                inteiro--
            } else {
                return inteiro
            }
        }
    }

}

// funcao que gera a hash da string peseudo aleartoria + nome + nonce
// a partir da hash e criada a hmac com a chave gerada no diffiehellman
func geraHmac (str string, nome string, nonce int, chavePrivada string) []byte {
    h := sha256.New()
    concatenado := str + nome + strconv.Itoa(nonce)
    h.Write([]byte(concatenado))
    hash := h.Sum(nil)
    m := hmac.New(sha256.New, []byte(chavePrivada))
    m.Write(hash)
    hmac := m.Sum(nil)
    return hmac
}

//funcao que gera as variaveis e realiza os calculos do diffiehellman
//tambem envia o nonce a ser utilziado na comunicacao
func diffieHellman (conn net.Conn) (string, int, int) {
    var dh Diffie
    
    //gerar inteiro
    dh.Dinteiro = int64(geraInt(false))
    //gerar primo
    dh.Dprimo = int64(geraInt(true))
    //gerar chave secreta 
    secreto := int64(geraInt(false))

    //calculo da chave publica do client
    calculo := new(big.Int)
    calculo = calculo.Mod(calculo.Exp(big.NewInt(int64(dh.Dinteiro)), big.NewInt(int64(secreto)), nil), big.NewInt(int64(dh.Dprimo)))
    dh.Dchave_publica = int64(calculo.Uint64())

    //definicao do nonce para envio ao servidor
    nonce := 100
    
    //montagem e envio da mensagem
    encdif := gob.NewEncoder(conn)
    decdif := gob.NewDecoder(conn)
    dif := &Diffie{dh.Dinteiro, dh.Dprimo, dh.Dchave_publica, nonce, nonce+100}
    encdif.Encode(dif)
   
    //aguarda chave publica do server
    retorno := &Diffie{}
    decdif.Decode(retorno)
    chave_publica_server := retorno.Dchave_publica
    
    //calculo da chave secreta do client
    calculo = calculo.Mod(calculo.Exp(big.NewInt(int64(chave_publica_server)), big.NewInt(int64(secreto)), nil), big.NewInt(int64(dh.Dprimo)))
    chave_secreta_client := int64(calculo.Uint64())

    //retorna a chave secreta, o nonce inicial e o nonce final
    return strconv.FormatInt(chave_secreta_client, 10), nonce, nonce+100
}

//funcao que realiza o envio das mensagens para o servidor
func enviar (conn net.Conn, nome string, str string, hmac []byte, nonce int) {
    //instancias
    encoder := gob.NewEncoder(conn)
    //gera a mensagem
    msg := &Mensagem{nome, str, hmac, nonce}
    //envio da mensagem
    encoder.Encode(msg)
    //aguarda retorno
    retorno, err := bufio.NewReader(conn).ReadString('\n')
    if err != nil {
        fmt.Println("Erro ao receber a resposta do servidor! ", err)
    }  
    fmt.Println(retorno);
}



func main() {
    fmt.Println("Iniciando o cliente..\n");
    //Recebendo argumentos
    var nome, ip, porta string
    var tam_mensagem, n_mensagens int
    flag.StringVar(&nome, "nome", "Alice", "Nome do cliente")
    flag.StringVar(&ip, "ip", "127.0.0.1", "IP do servidor")
    flag.StringVar(&porta, "porta", "8080", "Porta do servidor")
    flag.IntVar(&n_mensagens, "n_mensagens", 3, "Numero de mensagens")
    flag.IntVar(&tam_mensagem, "tam_mensagem", 20, "Tamanho da mensagem")
    flag.Parse()

    //inicia a conexao
    conn, err := net.Dial("tcp", ip+":"+porta)
    if err != nil {
       fmt.Println("Servidor indisponivel! ", err)
       os.Exit(0)
    }

    //chama a funcao que gera o diffiehellman e nonce
    chavePrivada, nonce_inicial, nonce_final := diffieHellman(conn)

    //inicializacao do nonce
    nonce := nonce_inicial
    for i:=0; i < n_mensagens; i++ {
    	//reinicializacao do valor do nonce
        if nonce > nonce_final {
    		nonce = nonce_inicial
    	}
        //chama a funcao que gera a strig pseudo-aleartoria
        str := geraString(tam_mensagem)
        //chama a funcao que envia a mensagem para o servidor
        enviar(conn, nome, str, geraHmac(str, nome, nonce, chavePrivada), nonce)
        nonce++


    }
    //encerra a conexao
    conn.Close()
}