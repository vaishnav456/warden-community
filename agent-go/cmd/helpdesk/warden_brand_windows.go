package main

import (
	"math"
	"unsafe"
)

// wardenMark reproduces the application's 40x40 mark from templates/base.html:
// shield frame, W route and spark. Keep this geometry shared by all native UI.
func (s *workspaceSurface) wardenMark(x, y, size int32, color uint32) {
	scale := float64(size) / 40
	point := func(a, b float64) [2]float64 { return [2]float64{float64(x) + a*scale, float64(y) + b*scale} }
	stroke := func(points [][2]float64, width float64) {
		mapped := make([][2]float64, len(points))
		for i, p := range points {
			mapped[i] = point(p[0], p[1])
		}
		s.brandStroke(mapped, width*scale, color)
	}
	shield := [][2]float64{{20, 2.8}, {34, 8.7}, {34, 19.5}}
	curve := func(a, b, c, d [2]float64) {
		for i := 1; i <= 16; i++ {
			t := float64(i) / 16
			u := 1 - t
			shield = append(shield, [2]float64{u*u*u*a[0] + 3*u*u*t*b[0] + 3*u*t*t*c[0] + t*t*t*d[0], u*u*u*a[1] + 3*u*u*t*b[1] + 3*u*t*t*c[1] + t*t*t*d[1]})
		}
	}
	curve([2]float64{34, 19.5}, [2]float64{34, 28.3}, [2]float64{28.7, 33.6}, [2]float64{20, 37.2})
	curve([2]float64{20, 37.2}, [2]float64{11.3, 33.6}, [2]float64{6, 28.3}, [2]float64{6, 19.5})
	shield = append(shield, [2]float64{6, 8.7}, [2]float64{20, 2.8})
	stroke(shield, 1.8)
	stroke([][2]float64{{11.5, 13.2}, {15.6, 27.3}, {20, 18.8}, {24.4, 27.3}, {28.5, 13.2}}, 2.8)
	stroke([][2]float64{{20, 7.8}, {20, 12.1}}, 1.6)
	stroke([][2]float64{{17.8, 10}, {22.2, 10}}, 1.6)
}

// Brush-filled floating-point polygons avoid the Windows float-argument ABI
// while retaining subpixel curves and round stroke joins at small icon sizes.
func (s *workspaceSurface) brandStroke(points [][2]float64, width float64, color uint32) {
	if len(points) < 2 || width <= 0 {
		return
	}
	var brush uintptr
	workspaceGDIPlus.NewProc("GdipCreateSolidFill").Call(uintptr(color), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	defer workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
	fill := func(pairs []float32) {
		workspaceGDIPlus.NewProc("GdipFillPolygon").Call(s.graphics, brush, uintptr(unsafe.Pointer(&pairs[0])), uintptr(len(pairs)/2), 0)
	}
	r := width / 2
	for i, p := range points {
		if i > 0 {
			a := points[i-1]
			dx, dy := p[0]-a[0], p[1]-a[1]
			length := math.Hypot(dx, dy)
			if length > 0 {
				nx, ny := -dy/length*r, dx/length*r
				fill([]float32{float32(a[0] + nx), float32(a[1] + ny), float32(p[0] + nx), float32(p[1] + ny), float32(p[0] - nx), float32(p[1] - ny), float32(a[0] - nx), float32(a[1] - ny)})
			}
		}
		cap := make([]float32, 0, 32)
		for j := 0; j < 16; j++ {
			theta := float64(j) * math.Pi / 8
			cap = append(cap, float32(p[0]+r*math.Cos(theta)), float32(p[1]+r*math.Sin(theta)))
		}
		fill(cap)
	}
}
