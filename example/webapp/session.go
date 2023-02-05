package webapp

import "time"

var mySession = map[string]interface{}{}

func getFromSession(key string) interface{} {
	return mySession[key]
}

func setToSession(key string, value interface{}, duration time.Duration) {
	mySession[key] = value

	go func() {
		time.Sleep(duration)
		delete(mySession, key)
	}()
}
