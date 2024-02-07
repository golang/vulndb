// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package color

const (
	escape = "\033["
	end    = "m"

	// Reset all attributes and colors to their defaults.
	Reset = escape + "0" + end

	// Attribute codes
	Bold      = escape + "1" + end
	Faint     = escape + "2" + end
	Underline = escape + "4" + end
	Blink     = escape + "5" + end

	// Foreground colors
	Black   = escape + "30" + end
	Red     = escape + "31" + end
	Green   = escape + "32" + end
	Yellow  = escape + "33" + end
	Blue    = escape + "34" + end
	Magenta = escape + "35" + end
	Cyan    = escape + "36" + end
	White   = escape + "37" + end

	// Background colors
	BlackBG   = escape + "40" + end
	RedBG     = escape + "41" + end
	GreenBG   = escape + "42" + end
	YellowBG  = escape + "43" + end
	BlueBG    = escape + "44" + end
	MagentaBG = escape + "45" + end
	CyanBG    = escape + "46" + end
	WhiteBG   = escape + "47" + end

	// High intensity foreground colors
	BlackHi   = escape + "90" + end
	RedHi     = escape + "91" + end
	GreenHi   = escape + "92" + end
	YellowHi  = escape + "93" + end
	BlueHi    = escape + "94" + end
	MagentaHi = escape + "95" + end
	CyanHi    = escape + "96" + end
	WhiteHi   = escape + "97" + end

	// High intensity background colors
	BlackHiBG   = escape + "100" + end
	RedHiBG     = escape + "101" + end
	GreenHiBG   = escape + "102" + end
	YellowHiBG  = escape + "103" + end
	BlueHiBG    = escape + "104" + end
	MagentaHiBG = escape + "105" + end
	CyanHiBG    = escape + "106" + end
	WhiteHiBG   = escape + "107" + end
)
