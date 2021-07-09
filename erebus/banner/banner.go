package banner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// The banner message
func Display() {
	// Banner
	const banner = `	



    ______          __              
   / ____/_______  / /_  __  _______
  / __/ / ___/ _ \/ __ \/ / / / ___/
 / /___/ /  /  __/ /_/ / /_/ (__  ) 
/_____/_/   \___/_.___/\__,_/____/  v1.0-dev

`

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msg("\t\tgithub.com/ethicalhackingplayground\n\n")

	gologger.Info().Msg("Use with caution. You are responsible for your actions\n")
	gologger.Info().Msg("Developers assume no liability and are not responsible for any misuse or damage.\n\n")
}
