"""Abre imagem uma vez; calcula características compartilhadas sem NumPy/OpenCV."""
from collections import Counter
from io import BytesIO
from math import log2, sqrt, cos, pi
import warnings
from PIL import Image, ImageOps, UnidentifiedImageError
from .input_data import error
from plugins.scimg import config

ALLOWED = {"JPEG", "PNG", "WEBP", "BMP", "TIFF"}

def _mean(data):
    return sum(data) / len(data) if data else 0.0

def _var(data):
    if not data:
        return 0.0
    m = _mean(data)
    return _mean([(v-m)*(v-m) for v in data])

def _entropy_hist(hist):
    n = sum(hist)
    return -sum((x/n) * log2(x/n) for x in hist if x) if n else 0.0

def _cv(data):
    mean = _mean(data)
    return sqrt(_var(data)) / (mean + 1e-6)

from plugins.scimg.parsers.image_parser import safe_metadata as _safe_metadata


# DCT 8x8 separável, implementada em Python puro. Usa blocos da amostra.
_DCT = [[cos((2*x+1)*u*pi/16) for x in range(8)] for u in range(8)]

def _frequency_metrics(gray, w, h):
    selected=[]
    for y in (0, max(0,(h-8)//2), h-8):
        for x in (0, max(0,(w-8)//2), w-8):
            if (x,y) not in selected:
                selected.append((x,y))
    totals=[]; highs=[]; lows=[]; peaks=[]; orient=[]; sparse=[]
    for x,y in selected:
        block=[[gray[(y+dy)*w+x+dx]-128 for dx in range(8)] for dy in range(8)]
        temp=[[sum(_DCT[u][dx]*block[dy][dx] for dx in range(8)) for u in range(8)] for dy in range(8)]
        ac=[]
        for v in range(8):
            for u in range(8):
                if u==0 and v==0: continue
                coeff=sum(_DCT[v][dy]*temp[dy][u] for dy in range(8))
                ac.append((u,v,coeff*coeff))
        energy=sum(z for u,v,z in ac)
        if energy<1: continue
        totals.append(energy)
        highs.append(sum(z for u,v,z in ac if u+v>7)/energy)
        lows.append(sum(z for u,v,z in ac if u+v<=3)/energy)
        peaks.append(max(z for u,v,z in ac)/energy)
        horiz=sum(z for u,v,z in ac if u>v)
        vert=sum(z for u,v,z in ac if v>u)
        orient.append(abs(horiz-vert)/energy)
        mx=max(z for u,v,z in ac)
        sparse.append(sum(z<mx*.0001 for u,v,z in ac)/len(ac))
    return {
        "freq_high_band":_mean(highs) if highs else None,
        "freq_low_band":_mean(lows) if lows else None,
        "freq_peak_ratio":_mean(peaks) if peaks else None,
        "freq_directionality":_mean(orient) if orient else None,
        "freq_sparsity":_mean(sparse) if sparse else None,
    }

def _metrics(im, jpeg_native=None):
    rgb = im.convert("RGB")
    w, h = rgb.size
    px = list(rgb.get_flattened_data() if hasattr(rgb, "get_flattened_data") else rgb.getdata())
    gray = [round(.299*r + .587*g + .114*b) for r, g, b in px]
    n = len(gray)
    hist = [0] * 256
    for g in gray:
        hist[g] += 1
    s = sorted(gray)
    percentile = lambda q: s[int((n-1)*q)]
    mean = _mean(gray)
    var = _var(gray)
    edge = []; lap = []; res = []; equal = 0
    horizontal = []; vertical = []; rgb_delta = []; channel_edge_delta = []
    for y in range(1, h-1):
        row = y*w
        for x in range(1, w-1):
            i = row+x
            dx = abs(gray[i+1]-gray[i-1]) / 2
            dy = abs(gray[i+w]-gray[i-w]) / 2
            horizontal.append(dx); vertical.append(dy)
            edge.append((dx+dy)/2)
            lap.append(abs(4*gray[i]-gray[i-1]-gray[i+1]-gray[i-w]-gray[i+w])/4)
            a = (gray[i-1]+gray[i+1]+gray[i-w]+gray[i+w]) / 4
            res.append(abs(gray[i]-a))
            equal += px[i] == px[i+1]
            r,g,b = px[i]
            rgb_delta.append((abs(r-g)+abs(g-b)+abs(r-b))/3)
            nr,ng,nb = px[i+1]
            channel_edge_delta.append(max(abs(r-nr),abs(g-ng),abs(b-nb)) - min(abs(r-nr),abs(g-ng),abs(b-nb)))
    blocks = []; entropies = []; residual_blocks = []
    for y in range(0,h,16):
        for x in range(0,w,16):
            tile = [gray[yy*w+xx] for yy in range(y,min(y+16,h)) for xx in range(x,min(x+16,w))]
            if len(tile) < 64:
                continue
            blocks.append(_var(tile))
            residual_blocks.append(_mean([abs(tile[j]-tile[j-1]) for j in range(1,len(tile))]))
            cnt = Counter(v//16 for v in tile)
            entropies.append(_entropy_hist(list(cnt.values())))
    peak = max(hist)/n
    unique_colors = len(set(px))/n
    unique_luma = sum(1 for x in hist if x)/256
    sat_values = []
    for r,g,b in px:
        top = max(r,g,b); bottom = min(r,g,b)
        sat_values.append((top-bottom)/top if top else 0)
    # Repetições de linhas/colunas: distância de padrões de pixels, não semântica.
    rows = [tuple(gray[y*w:(y+1)*w]) for y in range(h)]
    cols = [tuple(gray[x+y*w] for y in range(h)) for x in range(w)]
    row_repeat = (len(rows)-len(set(rows)))/len(rows)
    col_repeat = (len(cols)-len(set(cols)))/len(cols)
    mirror_x = _mean([abs(gray[y*w+x]-gray[y*w+(w-1-x)]) for y in range(h) for x in range(w//2)])/255
    mirror_y = _mean([abs(gray[y*w+x]-gray[(h-1-y)*w+x]) for y in range(h//2) for x in range(w)])/255
    # Blocos 8x8 em baixa resolução: medidas de repetição e regularidade.
    tiles=[]
    for y in range(0,h-7,8):
        for x in range(0,w-7,8):
            vals = [gray[(y+yy)*w+(x+xx)]//16 for yy in range(8) for xx in range(8)]
            tiles.append(tuple(vals))
    repeat_tiles = (len(tiles)-len(set(tiles)))/len(tiles) if tiles else 0
    stripe_rows = [_mean([abs(gray[y*w+x]-gray[(y-1)*w+x]) for x in range(w)]) for y in range(1,h)]
    stripe_cols = [_mean([abs(gray[y*w+x]-gray[y*w+x-1]) for y in range(h)]) for x in range(1,w)]
    # JPEG: analisar na resolução original (sem reamostragem) e somente se JPEG.
    blockiness = None
    if jpeg_native is not None:
        j = jpeg_native.convert("L")
        jw,jh = j.size
        vals = list(j.get_flattened_data() if hasattr(j, "get_flattened_data") else j.getdata())
        boundary=[]; interior=[]
        for y in range(jh):
            for x in range(1,jw):
                d = abs(vals[y*jw+x]-vals[y*jw+x-1])
                (boundary if x%8==0 else interior).append(d)
        for y in range(1,jh):
            for x in range(jw):
                d = abs(vals[y*jw+x]-vals[(y-1)*jw+x])
                (boundary if y%8==0 else interior).append(d)
        blockiness = _mean(boundary)/(_mean(interior)+1)
    m = {
        "luma_mean": mean/255, "luma_std": sqrt(var)/127.5,
        "luma_entropy": _entropy_hist(hist)/8,
        "dark_fraction": sum(hist[:32])/n,
        "bright_fraction": sum(hist[224:])/n,
        "midtone_fraction": sum(hist[96:160])/n,
        "luma_range": (percentile(.9)-percentile(.1))/255,
        "clipped_fraction": (hist[0]+hist[255])/n,
        "hist_mode": peak,
        "luma_occupancy": unique_luma,
        "unique_color_ratio": unique_colors,
        "saturation_mean": _mean(sat_values),
        "saturation_std": sqrt(_var(sat_values)),
        "saturated_fraction": sum(v>.85 for v in sat_values)/n,
        "gray_fraction": sum(v<.04 for v in sat_values)/n,
        "color_difference": _mean(rgb_delta)/255,
        "color_edge_discordance": _mean(channel_edge_delta)/255,
        "edge_density": sum(e>20 for e in edge)/len(edge) if edge else 0,
        "edge_strength": _mean(edge)/127.5,
        "horizontal_gradient": _mean(horizontal)/127.5,
        "vertical_gradient": _mean(vertical)/127.5,
        "gradient_imbalance": abs(_mean(horizontal)-_mean(vertical))/127.5,
        "laplacian_mean": _mean(lap)/255,
        "laplacian_variation": sqrt(_var(lap))/127.5,
        "residual_mean": _mean(res)/127.5,
        "residual_spread": sqrt(_var(res))/127.5,
        "residual_cv": min(_cv(res),10)/10,
        "adjacent_equal_fraction": equal/len(edge) if edge else 0,
        "flat_tile_fraction": sum(v<20 for v in blocks)/len(blocks) if blocks else 0,
        "high_variance_tile_fraction": sum(v>2000 for v in blocks)/len(blocks) if blocks else 0,
        "tile_variance_cv": min(_cv(blocks),10)/10,
        "tile_entropy_mean": _mean(entropies)/4,
        "tile_entropy_std": sqrt(_var(entropies))/2,
        "residual_tile_cv": min(_cv(residual_blocks),10)/10,
        "row_repetition": row_repeat,
        "column_repetition": col_repeat,
        "tile_repetition": repeat_tiles,
        "mirror_x_similarity": 1-mirror_x,
        "mirror_y_similarity": 1-mirror_y,
        "stripe_row_cv": min(_cv(stripe_rows),10)/10,
        "stripe_col_cv": min(_cv(stripe_cols),10)/10,
        "stripe_row_peak": max(stripe_rows,default=0)/(mean+1),
        "stripe_col_peak": max(stripe_cols,default=0)/(mean+1),
        "jpeg_blockiness": blockiness,
        "compression_ratio": None,
    }
    m.update(_frequency_metrics(gray,w,h))
    return m

def collect_image(ctx):
    limit = int(config.get("scanner", {}).get("max_pixels", 12_000_000))
    sample_side = int(config.get("scanner", {}).get("sample_side", 160))
    if not 64 <= sample_side <= 384:
        return error("invalid_config", "sample_side fora de 64..384")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(ctx.content_bytes)) as original:
                if original.format not in ALLOWED:
                    return error("unsupported_format", "Formato de imagem não suportado")
                w,h=original.size
                if w<32 or h<32 or w*h>limit:
                    return error("invalid_dimensions", "Imagem muito pequena ou com pixels demais")
                if getattr(original,"n_frames",1)>1:
                    return error("animated_unsupported", "Imagens com múltiplos quadros não são suportadas")
                txt=_safe_metadata(original)
                jpeg=original.crop((0,0,min(256,w),min(256,h))) if original.format=="JPEG" else None
                image=ImageOps.exif_transpose(original)
                image.thumbnail((sample_side,sample_side),Image.Resampling.LANCZOS)
                if image.width<16 or image.height<16:
                    return error("invalid_dimensions", "Amostra insuficiente")
                metrics=_metrics(image,jpeg)
                ctx.metadata={"width":w,"height":h,"format":original.format,
                              "mode":original.mode,"sample_size":image.size}
                ctx.features={"metrics":metrics,"metadata_text":txt.lower(),
                              "metadata_available":bool(txt),"format":original.format}
                return None
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombWarning, Image.DecompressionBombError, MemoryError):
        return error("invalid_image", "Imagem inválida, corrompida ou insegura")
