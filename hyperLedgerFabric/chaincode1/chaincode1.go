package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// ChainCode的Go代码需要定义一个SimpleChaincode这样一个struct，
// 然后在该struct上定义Init和Invoke两个函数，然后还要定义一个main函数，
// 作为ChainCode的启动入口

type SimpleChaincode struct {
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err.Error())
	}
}

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	fmt.Println("invoke is running " + function)
	if function == "test1" { //自定义函数名称
		return t.test1(stub, args) //定义调用的函数
	}
	return shim.Error("Received unknown function invocation")
}

func (t *SimpleChaincode) test1(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	return shim.Success([]byte("Called test1"))
}

type Student struct {
	Id   int
	Name string
}

func (t *SimpleChaincode) testStateOp(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	student1 := Student{1, "ljs"}
	key := "Student:" + strconv.Itoa(student1.Id) //Key格式为 Student:{Id}
	studentJsonBytes, err := json.Marshal(student1)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(key, studentJsonBytes)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte("Saved Student!"))
}

// 前面在进行数据库的增删改查的时候，都需要用到Key，而我们使用的是我们自己定义的Key格式：
// {StructName}:{Id}，这是有单主键Id还比较简单，如果我们有多个列做联合主键怎么办？
// 实际上，ChainCode也为我们提供了生成Key的方法CreateCompositeKey，通过这个方法，
// 我们可以将联合主键涉及到的属性都传进去，并声明了对象的类型即可。
// 以选课表为例，里面包含了以下属性
type ChooseCourse struct {
	CourseNumber string //	开课编号
	StudentID    int    // id
	Confirm      bool   // 是否确认
}

// 其中CourseNumber+StudentId构成了这个对象的联合主键，我们要获得生成的复核主键，那么可写为：
// cc:=ChooseCourse{"CS101",123,true}
// var key1,_= stub.CreateCompositeKey("ChooseCourse",[]string{cc.CourseNumber,strconv.Itoa(cc.StudentId)})
// fmt.Println(key1)
// 【注：其实Fabric就是用U+0000来把各个字段分割开的，因为这个字符太特殊，所以很适合做分割】

// 既然有组合那么就有拆分，当我们从数据库中获得了一个复合键的Key之后，怎么知道其具体是由
// 哪些字段组成的呢。其实就是用U+0000把这个复合键再Split开，得到结果中第一个是objectType，
// 剩下的就是复合键用到的列的值。
// objType,attrArray,_:= stub.SplitCompositeKey(key1)
// fmt.Println("Object:"+objType+" ,Attributes:"+strings.Join(attrArray,"|"))

// 获得当前用户GetCreator() ([]byte, error)
// 这个方法可以获得调用这个ChainCode的客户端的用户的证书，这里虽然返回的是byte数组，
// 但是其实是一个字符串,内容格式如下：
// -----BEGIN CERTIFICATE-----
// MIICGjCCAcCgAwIBAgIRAMVe0+QZL+67Q+R2RmqsD90wCgYIKoZIzj0EAwIwczEL
// MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
// cmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh
// Lm9yZzEuZXhhbXBsZS5jb20wHhcNMTcwODEyMTYyNTU1WhcNMjcwODEwMTYyNTU1
// WjBbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
// U2FuIEZyYW5jaXNjbzEfMB0GA1UEAwwWVXNlcjFAb3JnMS5leGFtcGxlLmNvbTBZ
// MBMGByqGSM49AgEGCCqGSM49AwEHA0IABN7WqfFwWWKynl9SI87byp0SZO6QU1hT
// JRatYysXX5MJJRzvvVsSTsUzQh5jmgwkPbFcvk/x4W8lj5d2Tohff+WjTTBLMA4G
// A1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsGA1UdIwQkMCKAIO2os1zK9BKe
// Lb4P8lZOFU+3c0S5+jHnEILFWx2gNoLkMAoGCCqGSM49BAMCA0gAMEUCIQDAIDHK
// gPZsgZjzNTkJgglZ7VgJLVFOuHgKWT9GbzhwBgIgE2YWoDpG0HuhB66UzlA+6QzJ
// +jvM0tOVZuWyUIVmwBM=
// -----END CERTIFICATE-----
// 我们常见的需求是在ChainCode中获得当前用户的信息，方便进行权限管理。
// 那么我们怎么获得当前用户呢？我们可以把这个证书的字符串转换为Certificate对象。
// 一旦转换成这个对象，我们就可以通过Subject获得当前用户的名字。
func (t *SimpleChaincode) testCertificate(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	creatorByte, _ := stub.GetCreator()
	certStart := bytes.IndexAny(creatorByte, "-----BEGIN")
	if certStart == -1 {
		fmt.Errorf("No certificate found")
	}

	certText := creatorByte[certStart:]
	bl, _ := pem.Decode(certText)
	if bl == nil {
		fmt.Errorf("Could not decode the PEM structure")
	}

	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		fmt.Errorf("ParseCertificate failed")
	}

	uname := cert.Subject.CommonName
	fmt.Println("Name:" + uname)
	return shim.Success([]byte("Called testCertificate " + uname))
}

// 区间查询GetStateByRange(startKey, endKey string) (StateQueryIteratorInterface, error)
// 提供了对某个区间的Key进行查询的接口，适用于任何State DB。由于返回的是一个
// StateQueryIteratorInterface接口，我们需要通过这个接口再做一个for循环，
// 才能读取返回的信息，所有我们可以独立出一个方法，专门将该接口返回的数据以string的
// byte数组形式返回。这是我们的转换方法：
func getListResult(resultsIterator shim.StateQueryIteratorInterface) ([]byte, error) {
	defer resultsIterator.Close()

	// buffer is a JSON array containing QueryRecords
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")
	fmt.Printf("queryResult:\n%s\n", buffer.String())
	return buffer.Bytes(), nil
}

// 比如我们要查询编号从1号到3号的所有学生，那么我们的查询代码可以这么写：
func (t *SimpleChaincode) testRangeQuery(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	resultsIterator, err := stub.GetStateByRange("Student:1", "Student:3")
	if err != nil {
		return shim.Error("Query by Range failed")
	}
	students, err := getListResult(resultsIterator)
	if err != nil {
		return shim.Error("getListResult failed")
	}
	return shim.Success(students)
}

func getHistoryListResult(resultsIterator shim.HistoryQueryIteratorInterface) ([]byte, error) {

	defer resultsIterator.Close()
	// buffer is a JSON array containing QueryRecords
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		item, _ := json.Marshal(queryResponse)
		buffer.Write(item)
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")
	fmt.Printf("queryResult:\n%s\n", buffer.String())
	return buffer.Bytes(), nil
}

// 历史数据查询GetHistoryForKey(key string) (HistoryQueryIteratorInterface, error)
// 对同一个数据（也就是Key相同）的更改，会记录到区块链中，我们可以通过GetHistoryForKey
// 方法获得这个对象在区块链中记录的更改历史，包括是在哪个TxId，修改的数据，修改的时间戳，
// 以及是否是删除等。比如之前的Student:1这个对象，我们更改和删除过数据，现在要查询这个对象
// 的更改记录，那么对应代码为：
func (t *SimpleChaincode) testHistoryQuery(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	student1 := Student{1, "ljs"}
	key := "Student:" + strconv.Itoa(student1.Id)
	it, err := stub.GetHistoryForKey(key)
	if err != nil {
		return shim.Error(err.Error())
	}
	var result, _ = getHistoryListResult(it)
	return shim.Success(result)
}

// 调用另外的链上代码 InvokeChaincode(chaincodeName string, args [][]byte, channel string) pb.Response
// 这个比较好理解，就是在我们的链上代码中调用别人已经部署好的链上代码。比如官方提供的
// example02，我们要在代码中去实现a->b的转账，那么我们的代码应该如下：
// 这里需要注意，我们使用的是example02的链上代码的实例名mycc，而不是代码的名字example02.
func (t *SimpleChaincode) testInvokeChainCode(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	trans := [][]byte{[]byte("invoke"), []byte("a"), []byte("b"), []byte("11")}
	response := stub.InvokeChaincode("mycc", trans, "mychannel")
	fmt.Println(response.Message)
	return shim.Success([]byte(response.Message))
}

// 事件设置SetEvent(name string, payload []byte) error
// 当ChainCode提交完毕，会通过Event的方式通知Client。而通知的内容可以通过SetEvent设置。
// 事件设置完毕后，需要在客户端也做相应的修改
func (t *SimpleChaincode) testEvent(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	tosend := "Event send data is here!"
	err := stub.SetEvent("evtsender", []byte(tosend))
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}
