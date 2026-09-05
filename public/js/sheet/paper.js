export function getPaperScatterHTML() {
    var papers = [
        { p: 'p1', ix: 65, iy: 30, dx: -95, dy: -55, dr: '-35deg', dx2: -145, dy2: -85, dr2: '-55deg', w: 30, h: 38 },
        { p: 'p2', ix: 65, iy: 65, dx: -75, dy: -35, dr: '-20deg', dx2: -115, dy2: -60, dr2: '-40deg', w: 28, h: 36 },
        { p: 'p3', ix: 65, iy: 100, dx: -105, dy: -10, dr: '-50deg', dx2: -155, dy2: -20, dr2: '-70deg', w: 30, h: 38 },
        { p: 'p4', ix: 65, iy: 135, dx: -65, dy: 15, dr: '15deg', dx2: -100, dy2: 35, dr2: '35deg', w: 32, h: 40 },
        { p: 'p5', ix: 65, iy: 170, dx: -55, dy: 45, dr: '-60deg', dx2: -85, dy2: 70, dr2: '-85deg', w: 26, h: 34 },
        { p: 'p6', ix: 65, iy: 205, dx: -85, dy: 5, dr: '-30deg', dx2: -130, dy2: 15, dr2: '-50deg', w: 28, h: 36 },
        { p: 'p7', ix: 65, iy: 240, dx: -110, dy: 30, dr: '-45deg', dx2: -165, dy2: 50, dr2: '-65deg', w: 28, h: 38 },
        { p: 'p8', ix: 65, iy: 275, dx: -50, dy: 55, dr: '25deg', dx2: -75, dy2: 80, dr2: '45deg', w: 26, h: 34 },
        { p: 'p9', ix: 500, iy: 30, dx: 95, dy: -55, dr: '30deg', dx2: 145, dy2: -85, dr2: '50deg', w: 30, h: 38 },
        { p: 'p10', ix: 500, iy: 65, dx: 75, dy: -35, dr: '-25deg', dx2: 115, dy2: -60, dr2: '-45deg', w: 28, h: 36 },
        { p: 'p11', ix: 500, iy: 100, dx: 105, dy: -10, dr: '45deg', dx2: 155, dy2: -20, dr2: '65deg', w: 30, h: 38 },
        { p: 'p12', ix: 500, iy: 135, dx: 65, dy: 15, dr: '-20deg', dx2: 100, dy2: 35, dr2: '-40deg', w: 32, h: 40 },
        { p: 'p13', ix: 500, iy: 170, dx: 55, dy: 45, dr: '55deg', dx2: 85, dy2: 70, dr2: '75deg', w: 26, h: 34 },
        { p: 'p14', ix: 500, iy: 205, dx: 85, dy: 5, dr: '-35deg', dx2: 130, dy2: 15, dr2: '-55deg', w: 28, h: 36 },
        { p: 'p15', ix: 500, iy: 240, dx: 110, dy: 30, dr: '40deg', dx2: 165, dy2: 50, dr2: '60deg', w: 28, h: 38 },
        { p: 'p16', ix: 500, iy: 275, dx: 50, dy: 55, dr: '-10deg', dx2: 75, dy2: 80, dr2: '-30deg', w: 26, h: 34 }
    ];
    var fills = ['#f5f0e8', '#faf6ee', '#f2ede4', '#f7f3eb', '#fefcf8', '#f9f5ef', '#f4efe6', '#fdfbf7'];
    var strokes = ['#c8c0b8', '#d5d0c8', '#d0c8c0', '#c8c0b8', '#e0d8d0', '#d0c8c0', '#ccc', '#c8c0b8'];
    return papers.map(function (d, i) {
        var fi = i % 8;
        return '<div class="paper-p ' + d.p + '" style="--dr:' + d.dr + ';--dr2:' + d.dr2 + ';--dx:' + d.dx + 'px;--dy:' + d.dy + 'px;--dx2:' + d.dx2 + 'px;--dy2:' + d.dy2 + 'px;position:absolute;left:' + d.ix + 'px;top:' + d.iy + 'px;width:' + d.w + 'px;height:' + d.h + 'px;background:' + fills[fi] + ';border:0.5px solid ' + strokes[fi] + ';border-radius:2px;overflow:hidden;">' +
            '<div style="position:absolute;left:50%;top:50%;margin-left:-' + Math.round(d.w * 0.28) + 'px;margin-top:-' + Math.round(d.h * 0.28) + 'px;">' +
            '<svg viewBox="0 0 20 20" width="' + Math.round(d.w * 0.56) + '" height="' + Math.round(d.h * 0.56) + '"><polygon points="5,3 15,10 5,17" fill="#c0392b" opacity="0.85"/></svg>' +
            '</div>' +
            '</div>';
    }).join('');
}
