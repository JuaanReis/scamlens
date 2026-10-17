import json

def render(scan, target):
    # JSON escaping of untrusted filenames/messages prevents terminal control injection.
    lines = ["scfs :: static file scanner", ":: Status  " + scan['status']]
    if scan['status'] == 'error':
        lines.append(":: Error   " + json.dumps(scan['error'], ensure_ascii=True))
    else:
        lines.extend([":: Target  " + json.dumps(target['identity']['name'], ensure_ascii=True),
                      ":: Format  " + target['executable']['format'],
                      ":: SHA256  " + target['identity']['sha256'],
                      ":: Score   " + str(scan['result']['score']) + "/100  " + scan['result']['risk_level'],
                      ":: Verdict " + scan['result']['verdict']])
        for rule in scan['heuristics']:
            if rule['triggered']:
                lines.append("  ["+rule['severity']+"] "+rule['name']+" = "+str(rule['score']))
        lines.append(":: Static heuristic assessment; score is not a probability.")
        for warning in scan['warnings']:
            lines.append(":: Warning " + json.dumps(warning, ensure_ascii=True))
    return "\n".join(lines)
