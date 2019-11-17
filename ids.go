package main

import (
    "fmt"
    "os"
    "path/filepath" //Dir scan icin
    "crypto/sha256" //Sifreleme icin
    "encoding/hex"  //hex Cevirme icin
    "crypto/hmac"   //Hmac support
    "time"          //Sleep icin
    "io/ioutil"
    "strings"
    "runtime"       //OS tespiti icin
    "os/user"       //Username almak icin
    "encoding/gob"  //Serialization icin simple binary protocol
)

func sys_enum(){

    if runtime.GOOS == "windows" {
        fmt.Println("You are running on Windows")
        
        w, uacerr := os.Create("C:\\Windows\\uactest.txt")
        if uacerr != nil {
            fmt.Println("***********************************\nYou may not have admin privilages!\n***********************************")
            panic(uacerr)
        }
        defer w.Close()


    } else {
        fmt.Println("You are running on an OS other than Windows")  //Linux

        user, err := user.Current()
        if err != nil {
            panic(err)
        }
        //fmt.Println("Hi " + user.Name + " (id: " + user.Uid + ")")
        if (user.Uid != "0"){
            fmt.Println("***********************************\nYou may not have admin privilages!\n***********************************")
        }
        
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


func main() {

    sys_enum()
    filehashmap := make(map[string]string)

    if _, err := os.Stat("files.db"); os.IsNotExist(err) {  //Dosyayı okumaya çalış

        fmt.Println("DB File Can Not Be Found.")
            
        scanfiles(filehashmap)

        fmt.Println("Configuration Files Scanned!")
    
         dataFile, err := os.Create("files.db") 	// create a file
         if err != nil {
             fmt.Println(err)
             os.Exit(1)
         }
         dataEncoder := gob.NewEncoder(dataFile)      // serialize the data
         dataEncoder.Encode(filehashmap)
         dataFile.Close()
		
	}else{

        dataFile, err := os.Open("files.db")
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }
   
        dataDecoder := gob.NewDecoder(dataFile)
        err = dataDecoder.Decode(&filehashmap)
   
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }
   
        dataFile.Close()
   
        fmt.Println(filehashmap)  //Print recover file

        fmt.Println("DB File Found and recovered")

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
        }

            if (strings.Compare(hash_of_file, v) == 0){ //Yeni hash ile hashmapteki hash ayniysa
                _ = v // v is now "used"
            }else{
                fmt.Print(time.Now().Format("2006-01-02 15:04:05 "))
                fmt.Print(k)
                fmt.Println(" Changed!")
                filehashmap[k] = hash_of_file
            }
        }

        time.Sleep(500 * time.Millisecond)  //500ms uyu

    }


}