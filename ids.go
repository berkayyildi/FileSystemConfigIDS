package main

import (
    "fmt"           //Standart kütüphane
    "os"            //OS islemleri icin
    "path/filepath" //Dir scan icin
    "crypto/sha256" //Sifreleme icin
    "encoding/hex"  //hex Cevirme icin
    "crypto/hmac"   //Hmac support
    "time"          //Sleep icin
    "io/ioutil"     //Readfile icin
    "io"            //Dosya islemleri
    "strings"       //String comparison icin
    "runtime"       //OS tespiti icin
    "os/user"       //Username almak icin
    "encoding/gob"  //Serialization icin simple binary protocol
    "crypto/aes"    //AES kutuphanesi
    "crypto/cipher"
    "crypto/rand"
    "log"
    "errors"
    "bytes"         //Save etmeden once buffera al aes encript yap oyle yaz

)

func sys_enum(){

    if runtime.GOOS == "windows" {     //Windows ise Windows klasorune yazabiliyo mu
        fmt.Println("You are running on Windows")
        
        w, uacerr := os.Create("C:\\Windows\\uactest.txt")
        if uacerr != nil {
            fmt.Println("***********************************\nYou may not have admin privilages!\n***********************************")
            panic(uacerr)
        }
        defer w.Close()


    } else if runtime.GOOS == "linux" {     //Linux ise uid 0 mı
        fmt.Println("You are running on Linux")  //Linux

        user, err := user.Current()
        if err != nil {
            panic(err)
        }
        //fmt.Println("Hi " + user.Name + " (id: " + user.Uid + ")")
        if (user.Uid != "0"){
            fmt.Println("***********************************\nYou may not have admin privilages!\n***********************************")
        }
        
    }else{
        fmt.Println("Your OS does not supported!")  //Linux
    }

}

func getsha256hash(file string) string{

    data, err := ioutil.ReadFile(file)
    if err != nil {
        fmt.Println("File reading error: ", err)
        return "delete"
    }

    secret := "cse439hmacsecretkey"
    h := hmac.New(sha256.New, []byte(secret)) // Create a new HMAC by defining the hash type and the key (as byte array)
    h.Write([]byte(data))    // Write Data to it
    sha := hex.EncodeToString(h.Sum(nil))    // Get result and encode as hexadecimal string
    return sha
}

func scanfiles(filehashmap map[string]string){

    root := ""

    if runtime.GOOS == "windows" {
        root = "C:\\Users\\Berkay\\Desktop\\fs"  // c:\\
    }else{
        root = "/etc"  // c:\\
    }

    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

        if info.IsDir() {
            return nil
        }

        if runtime.GOOS == "windows" {  //Windows ise sadece ini dosyalarini kontrol et
            if filepath.Ext(path) != ".ini" {
                return nil
            }
        }else{
            if filepath.Ext(path) != ".conf" {  //Linux ise conf dosyalarına bak
                return nil
            }
        }

        filehashmap[path] = getsha256hash(path) //Hash map i doldur

        return nil
    })

    if err != nil {
        panic(err)
    }

}

func save(filehashmap map[string]string){

    cache_bytes := new(bytes.Buffer)                // Bos buffer ac
    dataEncoder := gob.NewEncoder(cache_bytes)      // serializer olustur
    dataEncoder.Encode(filehashmap)                 // Serialize the data

    readBuf, _ := ioutil.ReadAll(cache_bytes)      // cannot use buffer (type *bytes.Buffer) as type []byte in argument to w.Write covertion
    sifrelibuf, enc_err := encrypt(key, readBuf)   // Aes ile sifrele

    if enc_err != nil {
        log.Fatal(enc_err)
    }

    file, opn_err := os.OpenFile(dbname, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
     if opn_err != nil {
        log.Fatal(opn_err)
     }
     defer file.Close()

     _, wrt_err := file.Write(sifrelibuf)     //Byte lari dosyaya yaz
     if wrt_err != nil {
        log.Fatal(wrt_err)
     }


     

    file2, opn_err := os.OpenFile("dbcheck", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
    if opn_err != nil {
       log.Fatal(opn_err)
    }
    defer file.Close()

    _, wrt_err2 := file2.Write([]byte(getsha256hash(dbname)))     //Byte lari dosyaya yaz
    if wrt_err2 != nil {
       log.Fatal(wrt_err2)
    }


}

func recover(filehashmap map[string]string){

    datach, err2 := ioutil.ReadFile("dbcheck")
    if err2 != nil {
        fmt.Println("File reading error: ", err2)
    }
    
    saaadatach := string(datach[:])
    if (        strings.Compare(saaadatach, getsha256hash(dbname)) != 0        ){
        log.Fatal("DB Checksum Error! ")
    }

    enc_bin_data, err := ioutil.ReadFile(dbname) // b has type []byte
    if err != nil {
        log.Fatal(err)
    }


    cozulmusbuf, dec_err := decrypt(key, enc_bin_data)   // Aes ile sifrele

    if dec_err != nil {
        log.Fatal(dec_err)
    }

    b := bytes.NewBuffer(cozulmusbuf)

    dataDecoder := gob.NewDecoder(b)
    decser_err := dataDecoder.Decode(&filehashmap)

    if decser_err != nil {  //Eğer dosyada değişiklik olursa decode edemiyceh tata vericek
        log.Println("Database Corrupt!")
        log.Fatal(decser_err)
    }

}


func encrypt(key, text []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(text))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
    return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    if len(text) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }
    iv := text[:aes.BlockSize]
    text = text[aes.BlockSize:]
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(text, text)

    return text, nil
}



var dbname = "files.db"

var key  []byte //Global key degiskeni yarat

func main() {

    s := "76606670776c717c75776a6f606671646076606b66776c75716c6a6b6e607c24" //DB Encription key HEX and XOR ed with 5
    key, _ = hex.DecodeString(s)
    for i, b := range key {
        key[i] = b^5  // xor b on element of random
    }   //fmt.Printf("%s\n", key)
    
    sys_enum()

    filehashmap := make(map[string]string)

    if _, err := os.Stat(dbname); os.IsNotExist(err) {  //Dosyayı okumaya çalış

        fmt.Println("DB File Can Not Be Found.")
        scanfiles(filehashmap)
        fmt.Println("Configuration Files Scanned!")
        save(filehashmap)   //İlk çalıştırmadan sonra save al
		
	}else{

        recover(filehashmap)
        fmt.Println(filehashmap)  //Print recover file to debug
        fmt.Println("DB File Found and recovered")
        //Save etme zaten ayni sey
    }



    for {   //Sonsuz dongu
        
        for k, v := range filehashmap { //Hashmapteki her file icin
        // fmt.Printf("key[%s] value[%s]\n", k, v)

        hash_of_file := getsha256hash(k)

        if (strings.Compare(hash_of_file, "delete") == 0){
                delete(filehashmap, k)
                fmt.Print(time.Now().Format("2006-01-02 15:04:05 "))
                fmt.Print(k)
                fmt.Println(" Deleted!")
                save(filehashmap)   //Dosyaya da save et
        }

        if (strings.Compare(hash_of_file, v) == 0){ //Yeni hash ile hashmapteki hash ayniysa
                _ = v // v is now "used"
            }else{
                fmt.Print(time.Now().Format("2006-01-02 15:04:05 "))
                fmt.Print(k)
                fmt.Println(" Changed!")
                filehashmap[k] = hash_of_file
                save(filehashmap)   //Dosyaya da save et
            }
        }
        
        time.Sleep(500 * time.Millisecond)  //500ms uyu

    }


}