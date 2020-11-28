package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bunseokbot/Honey-V/cmd"
)

func introTitle() {
	fmt.Println(`	 _       _    _            _             _    _        _          _          _          _       
        / /\    / /\ /\ \         /\ \     _    /\ \ /\ \     /\_\       /\ \       /\ \       /\ \     
       / / /   / / //  \ \       /  \ \   /\_\ /  \ \\ \ \   / / /      /  \ \     /  \ \      \_\ \    
      / /_/   / / // /\ \ \     / /\ \ \_/ / // /\ \ \\ \ \_/ / /      / /\ \ \   / /\ \ \     /\__ \   
     / /\ \__/ / // / /\ \ \   / / /\ \___/ // / /\ \_\\ \___/ /      / / /\ \_\ / / /\ \ \   / /_ \ \  
    / /\ \___\/ // / /  \ \_\ / / /  \/____// /_/_ \/_/ \ \ \_/      / / /_/ / // / /  \ \_\ / / /\ \ \ 
   / / /\/___/ // / /   / / // / /    / / // /____/\     \ \ \      / / /__\/ // / /   / / // / /  \/_/ 
  / / /   / / // / /   / / // / /    / / // /\____\/      \ \ \    / / /_____// / /   / / // / /        
 / / /   / / // / /___/ / // / /    / / // / /______       \ \ \  / / /      / / /___/ / // / /         
/ / /   / / // / /____\/ // / /    / / // / /_______\       \ \_\/ / /      / / /____\/ //_/ /          
\/_/    \/_/ \/_________/ \/_/     \/_/ \/__________/        \/_/\/_/       \/_________/ \_\/
	`)
}

func main() {
	introTitle()

	// set logger
	fpLog, err := os.OpenFile("honeypot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer fpLog.Close()

	multiWriter := io.MultiWriter(fpLog, os.Stdout)
	log.SetOutput(multiWriter)

	multiWriter = io.MultiWriter(fpLog, os.Stderr)
	log.SetOutput(multiWriter)

	cmd.Execute()
}
