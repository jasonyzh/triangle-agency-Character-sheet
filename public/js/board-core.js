function BoardCore(canvasEl, { editable, role, imageBaseUrl, onImageMove, onImageResize, onImageClick, onImageRightClick, onNpcLineDblClick, onNpcLineRightClick, onMapLineRightClick, onImageDblClick }) {
    const self = this;
    this.canvas = canvasEl;
    this.editable = editable;
    this.role = role || 'manager';
    this.imageBaseUrl = imageBaseUrl || '';
    this.images = {};
    this.connections = [];
    this.npcConnections = [];
    this.onImageMove = onImageMove || (() => {});
    this.onImageResize = onImageResize || (() => {});
    this.onImageClick = onImageClick || (() => {});
    this.onImageRightClick = onImageRightClick || (() => {});
    this.onNpcLineDblClick = onNpcLineDblClick || (() => {});
    this.onNpcLineRightClick = onNpcLineRightClick || (() => {});
    this.onMapLineRightClick = onMapLineRightClick || (() => {});
    this.onImageDblClick = onImageDblClick || (() => {});
    this.selectedId = null;

    // Prevent browser right-click on canvas
    this.canvas.oncontextmenu = function() { return false; };

    // Map connections layer (blue, below images)
    this.mapSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.mapSvg.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;';
    this.canvas.appendChild(this.mapSvg);

    // NPC connections layer (colored, below images)
    this.npcSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.npcSvg.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:auto;z-index:0;';
    this.canvas.appendChild(this.npcSvg);

    const COLORS = { friendly: '#27ae60', hostile: '#c0392b', neutral: '#f1c40f', unknown: '#8e44ad' };

    this.addImage = function(data) {
        const el = document.createElement('div');
        el.className = 'board-img';
        el.dataset.id = data.id;
        el.dataset.isMapNode = data.isMapNode || 0;
        el.style.cssText = 'position:absolute;left:' + data.x + 'px;top:' + data.y + 'px;z-index:' + ((data.z || 0) + 2) + ';touch-action:none;user-select:none;-webkit-user-select:none;';

        const imgWrapper = document.createElement('div');
        imgWrapper.style.cssText = 'border:2px solid #d0d5dd;border-radius:4px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.08);overflow:hidden;line-height:0;';

        const img = document.createElement('img');
        img.src = (data.imageFile && data.imageFile.indexOf('http') === 0) ? data.imageFile : (this.imageBaseUrl + data.imageFile);
        img.draggable = false;
        img.style.cssText = 'width:' + data.w + 'px;height:auto;display:block;pointer-events:none;';
        imgWrapper.appendChild(img);
        el.appendChild(imgWrapper);

        const label = document.createElement('div');
        label.className = 'board-img-label';
        label.textContent = data.name || '';
        label.style.cssText = 'margin-top:2px;padding:1px 4px;line-height:16px;font-size:10px;text-align:center;color:white;background:#c0392b;border-radius:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
        el.appendChild(label);

        // Update container height once image loads
        img.onload = function() { el.style.height = (img.offsetHeight + 22) + 'px'; };
        if (data.h) { img.style.width = data.w + 'px'; el.style.height = data.h + 'px'; }
        img.onerror = function() { img.src = ''; };

        if (this.editable) {
            // Resize handle on imgWrapper (not el, since el includes label)
            const handle = document.createElement('div');
            handle.style.cssText = 'position:absolute;right:0;bottom:22px;width:14px;height:14px;background:rgba(192,57,43,0.6);cursor:nwse-resize;border-radius:2px;z-index:2;touch-action:none;';
            imgWrapper.appendChild(handle);

            handle.addEventListener('pointerdown', (e) => {
                e.stopPropagation(); e.preventDefault();
                try { handle.setPointerCapture(e.pointerId); } catch(err) {}
                self.bringToFront(data.id);
                const sX = e.clientX, sW = img.offsetWidth, sH = img.offsetHeight, ratio = sW / Math.max(1, sH);
                const onMove = (ev) => {
                    const nw = Math.max(40, sW + ev.clientX - sX);
                    img.style.width = nw + 'px';
                    el.style.height = (nw / ratio + 22) + 'px';
                    self.drawAll();
                };
                const onUp = () => {
                    document.removeEventListener('pointermove', onMove);
                    document.removeEventListener('pointerup', onUp);
                    self.onImageResize(data.id, img.offsetWidth, img.offsetWidth / ratio);
                };
                document.addEventListener('pointermove', onMove);
                document.addEventListener('pointerup', onUp);
            });

            el.addEventListener('pointerdown', (e) => {
                if (e.target === handle) return;
                e.stopPropagation();
                e.preventDefault();
                try { el.setPointerCapture(e.pointerId); } catch(err) {}
                self.onImageClick(data.id);
                const sX = e.clientX, sY = e.clientY, ol = el.offsetLeft, ot = el.offsetTop;
                const onMove = (ev) => {
                    if (!el._moved) { el._moved = true; self.bringToFront(data.id); }
                    el.style.left = Math.max(0, ol + ev.clientX - sX) + 'px';
                    el.style.top = Math.max(0, ot + ev.clientY - sY) + 'px';
                    self.drawAll();
                };
                const onUp = (ev) => { document.removeEventListener('pointermove', onMove); document.removeEventListener('pointerup', onUp); if (Math.abs(ev.clientX - sX) < 3 && Math.abs(ev.clientY - sY) < 3) { el._moved = false; return; } self.bringToFront(data.id); el._moved = false; self.onImageMove(data.id, el.offsetLeft, el.offsetTop); };
                document.addEventListener('pointermove', onMove); document.addEventListener('pointerup', onUp);
            });

            el.oncontextmenu = function(e) {
                e.preventDefault();
                self.onImageRightClick(data.id, e.clientX, e.clientY);
                return false;
            };
        }

        el.addEventListener('dblclick', () => {
            self.onImageDblClick(data.id);
            if (self.onRename) self.onRename(data.id, el.querySelector('.board-img-label').textContent);
        });

        this.canvas.appendChild(el);
        this.images[data.id] = el;
    };

    this.highlightImage = function(imageId) {
        this.clearHighlight();
        this.selectedId = imageId;
        const el = this.images[imageId];
        if (el) { el.style.border = '3px solid #27ae60'; el.style.borderRadius = '6px'; }
    };

    this.clearHighlight = function() {
        if (this.selectedId && this.images[this.selectedId]) {
            this.images[this.selectedId].style.border = '1px solid #e0e3e8';
        }
    this.selectedId = null;
    this.zCounter = 10;
    };

    this.moveImage = function(imageId, x, y) { const el = this.images[imageId]; if (el) { el.style.left = x + 'px'; el.style.top = y + 'px'; } };
    this.resizeImage = function(imageId, w, h) {
        const el = this.images[imageId];
        if (el) {
            var img = el.querySelector('img');
            if (img) img.style.width = w + 'px';
            el.style.height = (h + 22) + 'px';
        }
    };
    this.removeImage = function(imageId) { const el = this.images[imageId]; if (el) { el.remove(); delete this.images[imageId]; } };
    this.renameImage = function(imageId, name) { const el = this.images[imageId]; if (el) el.querySelector('.board-img-label').textContent = name; };

    this.bringToFront = function(imageId) {
        var el = this.images[imageId];
        if (el) { this.canvas.appendChild(el); }
    };

    this.loadImages = function(images) {
        this.mapSvg.innerHTML = '';
        this.npcSvg.innerHTML = '';
        Object.values(this.images).forEach(el => el.remove());
        this.images = {};
        images.forEach(img => {
            const posKey = this.role === 'player' ? 'p' : 'm';
            this.addImage({
                id: img.id, imageFile: img.image_lib_filename || img.imageFile || '',
                x: img[posKey + '_x'] || 100, y: img[posKey + '_y'] || 100,
                w: img[posKey + '_w'] || 120, h: img[posKey + '_h'] || 120,
                name: img.name || '', isMapNode: img.is_map_node,
                z: img.z_index || 0
            });
        });
        setTimeout(() => this.drawAll(), 100);
    };

    this.setConnections = function(connections) { this.connections = connections || []; this.drawMapConnections(); };
    this.setNpcConnections = function(connections) { this.npcConnections = connections || []; this.drawNpcConnections(); };

    this.drawAll = function() { this.drawMapConnections(); this.drawNpcConnections(); };

    function nearestEdge(el, targetCX, targetCY) {
        const img = el.querySelector('img');
        if (!img) return { x: el.offsetLeft + el.offsetWidth/2, y: el.offsetTop + el.offsetHeight/2 };
        const l = el.offsetLeft, t = el.offsetTop, iw = img.offsetWidth, eh = el.offsetHeight;
        const edges = [
            { x: l + iw / 2, y: t, dist: Math.hypot(l + iw/2 - targetCX, t - targetCY) },
            { x: l + iw / 2, y: t + eh, dist: Math.hypot(l + iw/2 - targetCX, t + eh - targetCY) },
            { x: l, y: t + eh / 2, dist: Math.hypot(l - targetCX, t + eh/2 - targetCY) },
            { x: l + iw, y: t + eh / 2, dist: Math.hypot(l + iw - targetCX, t + eh/2 - targetCY) }
        ];
        edges.sort((a, b) => a.dist - b.dist);
        return edges[0];
    }

    function drawLine(svg, ax, ay, bx, by, color, label, id, dashed) {
        const pathD = 'M' + ax + ',' + ay + ' C' + (ax + (bx-ax) * 0.25) + ',' + (ay + (by-ay) * 0.25) + ' ' + (ax + (bx-ax) * 0.75) + ',' + (ay + (by-ay) * 0.75) + ' ' + bx + ',' + by;

        // Invisible wide hit area
        const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        hit.setAttribute('class', 'conn-hit');
        hit.setAttribute('d', pathD);
        hit.setAttribute('stroke', 'transparent');
        hit.setAttribute('stroke-width', '14');
        hit.setAttribute('fill', 'none');
        hit.style.pointerEvents = 'stroke';
        hit.style.cursor = 'pointer';
        if (id) hit.setAttribute('data-conn-id', id);
        svg.appendChild(hit);

        // Visible line
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', pathD);
        path.setAttribute('stroke', color);
        path.setAttribute('stroke-width', '2.5');
        path.setAttribute('fill', 'none');
        if (dashed) path.setAttribute('stroke-dasharray', '8,4');
        if (id) path.setAttribute('data-conn-id', id);
        path.style.pointerEvents = 'none';
        svg.appendChild(path);

        if (label) {
            const mx = (ax + bx) / 2, my = (ay + by) / 2;
            // Darker opaque version of the line color
            const r = parseInt(color.slice(1,3), 16), g = parseInt(color.slice(3,5), 16), b2 = parseInt(color.slice(5,7), 16);
            const bg = '#' + [r,g,b2].map(c => Math.round(c * 0.35).toString(16).padStart(2,'0')).join('');

            const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            rect.setAttribute('x', mx - label.length * 3.5 - 8);
            rect.setAttribute('y', my - 10);
            rect.setAttribute('width', label.length * 7 + 16);
            rect.setAttribute('height', '20');
            rect.setAttribute('rx', '4');
            rect.setAttribute('ry', '4');
            rect.setAttribute('fill', bg);
            svg.appendChild(rect);

            const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            text.setAttribute('x', mx);
            text.setAttribute('y', my);
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('dominant-baseline', 'central');
            text.setAttribute('fill', 'white');
            text.setAttribute('font-size', '10');
            text.textContent = label;
            svg.appendChild(text);
        }
    }

    this.drawMapConnections = function() {
        this.mapSvg.innerHTML = '';
        (this.connections || []).forEach(conn => {
            const elA = this.images[conn.node_a], elB = this.images[conn.node_b];
            if (!elA || !elB) return;
            const imgA = elA.querySelector('img'), imgB = elB.querySelector('img');
            if (!imgA || !imgB) return;
            const acx = elA.offsetLeft + imgA.offsetWidth / 2;
            const acy = elA.offsetTop + elA.offsetHeight / 2;
            const bcx = elB.offsetLeft + imgB.offsetWidth / 2;
            const bcy = elB.offsetTop + elB.offsetHeight / 2;
            const a = nearestEdge(elA, bcx, bcy);
            const b = nearestEdge(elB, acx, acy);
            drawLine(this.mapSvg, a.x, a.y, b.x, b.y, '#2980b9', conn.label, conn.id, true);
        });

        // Right-click on map lines
        const paths = this.mapSvg.querySelectorAll('.conn-hit');
        paths.forEach(p => {
            p.oncontextmenu = function(e) {
                e.preventDefault(); e.stopPropagation();
                const connId = p.getAttribute('data-conn-id');
                if (connId) self.onMapLineRightClick(connId, e.clientX, e.clientY);
                return false;
            };
        });
    };

    this.drawNpcConnections = function() {
        this.npcSvg.innerHTML = '';
        (this.npcConnections || []).forEach(conn => {
            const elA = this.images[conn.node_a], elB = this.images[conn.node_b];
            if (!elA || !elB) return;
            const imgA = elA.querySelector('img'), imgB = elB.querySelector('img');
            if (!imgA || !imgB) return;
            const acx = elA.offsetLeft + imgA.offsetWidth / 2;
            const acy = elA.offsetTop + elA.offsetHeight / 2;
            const bcx = elB.offsetLeft + imgB.offsetWidth / 2;
            const bcy = elB.offsetTop + elB.offsetHeight / 2;
            const a = nearestEdge(elA, bcx, bcy);
            const b = nearestEdge(elB, acx, acy);
            const color = COLORS[conn.conn_type] || COLORS.unknown;
            drawLine(this.npcSvg, a.x, a.y, b.x, b.y, color, conn.label, conn.id, true);
        });

        // Double-click and right-click on NPC line hit areas
        const paths = this.npcSvg.querySelectorAll('.conn-hit');
        paths.forEach(p => {
            p.ondblclick = function(e) {
                const connId = p.getAttribute('data-conn-id');
                if (connId && self.onNpcLineDblClick) self.onNpcLineDblClick(connId);
            };
            p.oncontextmenu = function(e) {
                e.preventDefault(); e.stopPropagation();
                const connId = p.getAttribute('data-conn-id');
                if (connId) self.onNpcLineRightClick(connId, e.clientX, e.clientY);
                return false;
            };
        });
    };

    this.autoResizeCanvas = function() { this.canvas.style.height = Math.max(window.innerHeight * 0.55, 400) + 'px'; };
    this.autoResizeCanvas();
}
