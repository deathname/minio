package main

import (
	"os/exec"
	"fmt"
	_ "io/ioutil"
	_ "github.com/minio/minio/cmd"
	_ "github.com/minio/minio/cmd"
)

func main(){
	//exec.Command("python", "/Users/shakti.rajpandey/PycharmProjects/md5/main.py", "testfkdr2", "my-folder",  "QuickStart", "/Users/shakti.rajpandey/PycharmProjects/md5/quick").Run()
	//err := exec.Command("df").Run()
	//fmt.Println("Ouput: ")
	//fmt.Println(err)
	//
	//buf, _ := ioutil.ReadFile("/Users/shakti.rajpandey/PycharmProjects/md5/quick")
	//fmt.Println("File content :\n" + string(buf))
	//cmd := exec.Command("touch","/tmp/t.txt")
	cmd := exec.Command("bash", "/Users/shakti.rajpandey/go/src/github.com/minio/minio/cmd/gateway/azure/main/decrypt_azure_file.sh", "testfkdr2", "my-folder",  "QuickStart", "/Users/shakti.rajpandey/PycharmProjects/md5/quick")

	fmt.Println(cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil{
		fmt.Println(string(out))
	}

}
