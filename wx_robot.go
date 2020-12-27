package main

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//config.json
//{
//"wxAppid":"",
//"wxSecret":"",
//"selfToken":"",
//"wxGetAccessTokenTime":60,
//"wxGetAccessTokenUrl":"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s",
//"wxSendMsgUrl":"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=%s"
//
//}

type MsgInfo struct {
	XMLName       xml.Name `xml:"xml"`
	CToUserName   string   `xml:"ToUserName"`
	CFromUserName string   `xml:"FromUserName"`
	CCreateTime   int64    `xml:"CreateTime"`
	CMsgType      string   `xml:"MsgType"`
	CContent      string   `xml:"Content"`
	CMsgId        int64    `xml:"MsgId"`
	CEvent        string   `xml:"Event"`
	CEncrypt      string   `xml:"Encrypt"`
}

type Confg struct {
	AppId      string `json:"wxAppid"`
	WxSecret   string `json:"wxSecret"`
	InterVal   int    `json:"wxGetAccessTokenTime"`
	TokenUrl   string `json:"wxGetAccessTokenUrl"`
	SendMsgUrl string `json:"wxSendMsgUrl"`
	SelfToken  string `json:"selfToken"`
}

type Contentstu struct {
	Content string `json:"content"`
}

type PostBody struct {
	ToUser  string     `json:"touser"`
	MsgType string     `json:"msgtype"`
	Text    Contentstu `json:"text"`
}

var jsonRegex, _ = regexp.Compile(`{(?is)(.*|\s*)}`)
var sysCfg = &Confg{}
var wxAccessToken string

func decodeJsonObjectFromRequest(dst interface{}, r *http.Request) error {
	bodyJson, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = xml.Unmarshal(bodyJson, dst)
	return err
}

func readSysCfg() error {
	_, err := loadConfig(sysCfg, "config.json")
	return err
}

func loadConfig(data interface{}, file string) ([]byte, error) {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	matchs := jsonRegex.FindSubmatch(buf)
	if len(matchs) == 0 {
		return nil, errors.New("json format invalid:" + file)
	}
	err = json.Unmarshal(matchs[0], data)
	if err != nil {
		return nil, err
	}
	return matchs[0], nil
}

func GetWxAccessTokenLoop() {
	err := getWxAccessToken()
	if err != nil {
		log.Println(err.Error())
	}
	go func() {
		defer log.Panic()
		for {
			time.Sleep(time.Minute * time.Duration(sysCfg.InterVal))
			for {
				err = getWxAccessToken()
				if err != nil {
					fmt.Println(err.Error())
					time.Sleep(time.Second)
					continue
				}
				break
			}

		}
	}()
}

type getTokenResult struct {
	Access_token string `json:"access_token"`
	ErrCode      int    `json:"errcode"`
	ErrMsg       string `json:"errmsg"`
}

type Mpresp struct {
	CToUserName   string `json:"ToUserName"`
	CFromUserName string `json:"FromUserName"`
	CCreateTime   int64  `json:"CreateTime"`
	CMsgType      string `json:"MsgType"`
}

func getWxAccessToken() (err error) {
	getTokenUrl := fmt.Sprintf(sysCfg.TokenUrl, sysCfg.AppId, sysCfg.WxSecret)
	req, err := http.NewRequest("GET", getTokenUrl, nil)
	if err != nil {
		return
	}
	req.Header.Add("HTTPS_TYPE", "2")

	client := &http.Client{}
	var res *http.Response
	res, err = client.Do(req)
	if err != nil {
		return
	}

	var body []byte
	body, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return
	}

	r := new(getTokenResult)
	err = json.Unmarshal(body, r)
	if err != nil {
		return
	}
	if r.ErrCode != 0 {
		log.Println("get accesstoken fail,", r.ErrMsg)
		return
	}
	log.Println("wx token:", r.Access_token)
	return
}

func procRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.Query(), r.Method)
	if r.Method == "GET" {
		log.Println("procRequest URL:", r.URL.Query())
		checkSignature(w, r)
		return
	}
	request := &MsgInfo{}
	if err := decodeJsonObjectFromRequest(request, r); err != nil {
		log.Println("parse request message fail, ", err)
		return
	}

	log.Println("request:%v", *request)

	request.CFromUserName, request.CToUserName = request.CToUserName, request.CFromUserName
	request.CCreateTime = time.Now().Unix()

	//add some interesting action here
	switch request.CMsgType {
	case "event":
		fallthrough
	case "text":
		request.CContent = "bingo"
	default:
		request.CContent = "bingo"
	}
	resp, _ := xml.Marshal(request)
	w.Write(resp)
	log.Println("resp string=%v", string(resp))
}

func checkSignature(w http.ResponseWriter, r *http.Request) {
	var echostr string
	var timestamp string
	var nonce string
	var signature string

	queryForm := r.URL.Query()
	log.Println("peer host=%s query=%v", r.Host, queryForm)
	if len(queryForm["echostr"]) > 0 {
		echostr = queryForm["echostr"][0]
	}
	if len(queryForm["timestamp"]) > 0 {
		timestamp = queryForm["timestamp"][0]
	}
	if len(queryForm["nonce"]) > 0 {
		nonce = queryForm["nonce"][0]
	}
	if len(queryForm["signature"]) > 0 {
		signature = queryForm["signature"][0]
	}
	hash := sha1.Sum([]byte(strings.Join([]string{nonce, timestamp, sysCfg.SelfToken}, "")))
	if string(hash[:]) != signature {
		log.Println("check signature fail")
	}
	w.Write([]byte(echostr))
}

func main() {
	err := readSysCfg()
	if err != nil {
		fmt.Println(err)
		return
	}
	GetWxAccessTokenLoop()
	log.Println("Wexin Chat Service: Start!")
	http.HandleFunc("/", procRequest)
	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Fatal("Wexin Chat Service:ListenAndServe fail,", err)
	}
}
