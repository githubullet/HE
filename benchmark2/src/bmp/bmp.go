package bmp

type Header struct {
	Id       int16
	Filesize int32
	Res      int32
	Offset   int32
	Bihsize  int32
	Width    int32
	Height   int32
	Plane    int16
	Bpp      int16
	Comp     int32
	Bds      int32
	Hr       int32
	Vr       int32
	Usc      int32
	Ic       int32
}

type Pixel struct {
	R uint8
	G uint8
	B uint8
}
