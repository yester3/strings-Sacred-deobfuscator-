const { Client, GatewayIntentBits, SlashCommandBuilder, AttachmentBuilder, REST, Routes, Events } = require('discord.js');
const fs = require('fs');
const path = require('path');

// Tablas de encriptación Base84/Base64 extraídas estáticamente (fallback)
const defaultK = {'N':18,')':59,'9':12,'g':2,']':49,'"':6,'V':22,'k':3,'&':43,'B':54,'a':37,'b':25,"'":33,'T':53,':':0,'?':61,'7':80,'(':65,'\\':9,'M':56,'A':44,'J':78,'`':71,'=':27,'Q':32,'-':64,'6':30,'H':39,'L':48,'c':20,'Z':24,'t':66,'_':51,'p':67,'#':79,'*':3,'F':7,'o':36,'X':16,'u':52,'O':46,'1':38,'I':41,'r':13,'C':77,'K':1,'e':55,'m':17,'s':35,'j':50,'+':74,'P':70,',':31,'4':10,'d':8,'Y':62,'i':29,'$':11,'G':63,'^':4,'%':21,'3':72,'W':76,'l':15,'.':42,'h':47,'[':45,'S':28,'E':26,'0':34,'f':75,';':81,'R':58,'@':69,'<':60,'/':84,'n':23,'5':82,'U':73,'!':40,'q':68,'D':19,'2':5,'>':14,'8':57};
const defaultW = {'s':5,'q':19,'b':12,'G':33,'+':61,'H':63,'S':2,'M':4,'w':60,'T':45,'I':62,'1':30,'Q':31,'l':59,'o':40,'u':48,'X':0,'h':46,'i':18,'L':6,'J':13,'p':47,'Z':14,'O':3,'N':34,'x':54,'0':24,'R':51,'f':41,'6':16,'c':52,'r':57,'e':27,'7':17,'U':1,'a':9,'8':50,'D':58,'j':28,'2':29,'K':53,'4':36,'V':26,'A':20,'W':44,'y':42,'B':49,'/':32,'C':56,'9':22,'E':35,'n':25,'v':23,'5':55,'d':11,'Y':10,'t':7,'m':21,'k':8,'F':39,'P':43,'g':15,'3':38,'z':37};

// Evaluador de expresiones matemáticas seguras
function evalMath(expr) {
    if (!expr) return null;
    let sanitized = expr.replace(/\s/g, '');
    if (!/^[0-9+\-*/%().]+$/.test(sanitized)) return null;
    // Previene errores de sintaxis en JS con dobles negativos
    sanitized = sanitized.replace(/--/g, '- -');
    try {
        return Function('"use strict";return (' + sanitized + ')')();
    } catch {
        return null;
    }
}

// Desescapa strings de Lua a texto plano manualmente (evita fallos de JSON.parse)
function unescapeLuaString(s) {
    let res = '';
    let i = 0;
    while (i < s.length) {
        if (s[i] === '\\' && i + 1 < s.length) {
            let next = s[i + 1];
            if (next === 'a') { res += '\u0007'; i += 2; }
            else if (next === 'b') { res += '\b'; i += 2; }
            else if (next === 'f') { res += '\f'; i += 2; }
            else if (next === 'n') { res += '\n'; i += 2; }
            else if (next === 'r') { res += '\r'; i += 2; }
            else if (next === 't') { res += '\t'; i += 2; }
            else if (next === 'v') { res += '\u000b'; i += 2; }
            else if (next === '\\') { res += '\\'; i += 2; }
            else if (next === '"') { res += '"'; i += 2; }
            else if (next === "'") { res += "'"; i += 2; }
            else if (next === '\n') { res += '\n'; i += 2; }
            else if (/[0-9]/.test(next)) {
                let numStr = next;
                let j = i + 2;
                while (j < s.length && /[0-9]/.test(s[j]) && numStr.length < 3) {
                    numStr += s[j];
                    j++;
                }
                res += String.fromCharCode(parseInt(numStr, 8));
                i = j;
            } else {
                res += next;
                i += 2;
            }
        } else {
            res += s[i];
            i++;
        }
    }
    return res;
}

// Escapa texto plano a string de Lua válido
function escapeToLuaString(s) {
    if (typeof s !== 'string') s = String(s);
    return '"' + s
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t')
        + '"';
}

// Parsea las tablas K y W dinámicamente del script
function parseMap(mapStr) {
    const map = {};
    if (!mapStr) return map;
    const parts = mapStr.split(/[,;]/);
    for (let part of parts) {
        if (!part.trim()) continue;
        let match = part.match(/^\[?"((?:[^"\\]|\\.)*)"\]?=(.*)$/);
        if (match) {
            let key = unescapeLuaString(match[1]);
            let val = evalMath(match[2]);
            if (key.length === 1 && val !== null) map[key] = val;
        } else {
            match = part.match(/^([A-Za-z0-9])=(.*)$/);
            if (match) {
                let key = match[1];
                let val = evalMath(match[2]);
                if (val !== null) map[key] = val;
            }
        }
    }
    return map;
}

// Decodificador Base84 (Strings que empiezan con "C")
function decodeC(s, K) {
    let Q = s.substring(1);
    let m = Q.length;
    let res = [];
    let f = 0;
    while (f < m) {
        let j = m - f;
        let r = j >= 5 ? 5 : j;
        let p = 0;
        let valid = true;
        for (let i = 0; i < r; i++) {
            let ch = Q[f + i];
            if (K[ch] !== undefined) {
                p = p * 84 + K[ch];
            } else {
                valid = false;
                break;
            }
        }
        if (valid) {
            if (r === 5) {
                res.push(Math.floor(p / 16777216) % 256);
                res.push(Math.floor(p / 65536) % 256);
                res.push(Math.floor(p / 256) % 256);
                res.push(p % 256);
            } else if (r === 4) {
                res.push(Math.floor(p / 65536) % 256);
                res.push(Math.floor(p / 256) % 256);
                res.push(p % 256);
            } else if (r === 3) {
                res.push(Math.floor(p / 256) % 256);
                res.push(p % 256);
            } else if (r === 2) {
                res.push(p % 256);
            }
        }
        f += r;
    }
    return Buffer.from(res).toString('latin1');
}

// Decodificador Base64 (Strings que empiezan con "<")
function decodeLT(s, W) {
    let Q = s.substring(1);
    let m = Q.length;
    let res = [];
    let f = 0;
    let M = 0, E = 0;
    while (f < m) {
        let j = Q[f];
        let r = W[j];
        if (r !== undefined) {
            M += r * Math.pow(64, E);
            E++;
            if (E === 4) {
                E = 0;
                res.push(Math.floor(M / 65536) % 256);
                res.push(Math.floor(M / 256) % 256);
                res.push(M % 256);
                M = 0;
            }
        } else if (j === '=') {
            res.push(Math.floor(M / 65536) % 256);
            if (f < m - 1 && Q[f + 1] !== '=') {
                res.push(Math.floor((M % 65536) / 256));
            }
            break;
        }
        f++;
    }
    return Buffer.from(res).toString('latin1');
}

// Deobfuscador principal
function deobfuscate(code) {
    // 1. Extraer offset matemático y nombre de función dinámicamente
    const offsetMatch = code.match(/local\s+function\s+([a-zA-Z_]\w*)\s*\(\s*\w+\s*\)\s*return\s+Uh\s*\[\s*\w+\s*\+\s*\(?\s*([^)\]]+)\s*\)?\s*\]\s*end/);
    if (!offsetMatch) throw new Error("No se encontró la función de desencriptación.");
    const funcName = offsetMatch[1];
    const offset = evalMath(offsetMatch[2]);
    if (offset === null) throw new Error("No se pudo calcular el offset matemático.");

    // 2. Extraer y parsear tablas K y W dinámicamente
    const kMatch = code.match(/local\s+K\s*=\s*\{([\s\S]*?)\}/);
    const wMatch = code.match(/local\s+W\s*=\s*\{([\s\S]*?)\}/);
    const K = kMatch ? { ...defaultK, ...parseMap(kMatch[1]) } : defaultK;
    const W = wMatch ? { ...defaultW, ...parseMap(wMatch[1]) } : defaultW;

    // 3. Extraer array de strings Uh
    const uhMatch = code.match(/local\s+Uh\s*=\s*\{([\s\S]*?)\}\s*local\s+function/);
    if (!uhMatch) throw new Error("No se encontró la tabla de strings Uh.");
    
    const stringMatches = [...uhMatch[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)];
    let Uh = stringMatches.map(m => unescapeLuaString(m[1]));

    // 4. Extraer y aplicar intercambios (swaps) simulando el bucle while exacto del ofuscador
    const swapMatch = code.match(/ipairs\(\{(\{\{.*?\}\})\}\)/);
    if (swapMatch) {
        let swapStr = swapMatch[1].replace(/\{/g, '[').replace(/\}/g, ']').replace(/;/g, ',');
        try {
            const swaps = eval(swapStr);
            for (const pair of swaps) {
                let i1 = pair[0];
                let i2 = pair[1];
                // El ofuscador usa un bucle while que invierte la sección
                while (i1 < i2) {
                    [Uh[i1 - 1], Uh[i2 - 1]] = [Uh[i2 - 1], Uh[i1 - 1]];
                    i1 += 1;
                    i2 -= 1;
                }
            }
        } catch(e) { console.error("Error en swaps:", e); }
    }

    // 5. Decodificar todos los strings de Uh
    Uh = Uh.map(s => {
        if (typeof s !== 'string') return s;
        if (s.startsWith('C')) return decodeC(s, K);
        if (s.startsWith('<')) return decodeLT(s, W);
        return s;
    });

    // 6. Reemplazar llamadas a la función de desencriptación en el código
    let result = '';
    let i = 0;
    const funcCall = funcName + '(';
    while (i < code.length) {
        if (code.startsWith(funcCall, i)) {
            let depth = 1;
            let start = i + funcCall.length;
            let end = start;
            while (end < code.length && depth > 0) {
                if (code[end] === '(') depth++;
                else if (code[end] === ')') depth--;
                end++;
            }
            let expr = code.substring(start, end - 1);
            let val = evalMath(expr);
            
            if (val !== null) {
                let idx = val + offset;
                if (idx >= 1 && idx <= Uh.length) {
                    let str = Uh[idx - 1];
                    result += escapeToLuaString(str);
                    i = end;
                    continue;
                }
            }
        }
        result += code[i];
        i++;
    }

    // 7. Limpieza: Eliminar la basura del ofuscador para que el código quede limpio
    result = result.replace(/local\s+Uh\s*=\s*\{[\s\S]*?\}\s*local\s+function.*?end\s+end\s+end\s+do/g, '');
    result = result.replace(/local\s+K\s*=\s*\{.*?\}/g, '');
    result = result.replace(/local\s+W\s*=\s*\{.*?\}/g, '');
    result = result.replace(/local\s+p\s*=\s*string\.len.*?end\s+end\s+end\s+end\s+end\s+end/g, '');

    return result;
}

// === CONFIGURACIÓN DEL BOT DE DISCORD ===
const token = process.env.DISCORD_TOKEN;
if (!token) {
    console.error("Error: Debes proporcionar el DISCORD_TOKEN en las variables de entorno.");
    process.exit(1);
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const commands = [
    new SlashCommandBuilder()
        .setName('decrypt')
        .setDescription('Deobfusca un archivo Lua ofuscado')
        .addAttachmentOption(option => 
            option.setName('archivo')
                .setDescription('El archivo .lua ofuscado')
                .setRequired(true))
].map(command => command.toJSON());

client.once(Events.ClientReady, async () => {
    console.log(`Bot conectado como ${client.user.tag}`);
    
    try {
        const rest = new REST({ version: '10' }).setToken(token);
        console.log('Registrando comandos slash globalmente...');
        await rest.put(
            Routes.applicationCommands(client.user.id),
            { body: commands }
        );
        console.log('Comandos registrados exitosamente.');
    } catch (error) {
        console.error('Error al registrar los comandos:', error);
    }
});

client.on(Events.InteractionCreate, async interaction => {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.commandName === 'decrypt') {
        const attachment = interaction.options.getAttachment('archivo');
        
        if (!attachment) {
            return interaction.reply({ content: '❌ No se proporcionó ningún archivo.', ephemeral: true });
        }

        if (!attachment.name.endsWith('.lua') && !attachment.name.endsWith('.txt')) {
            return interaction.reply({ content: '❌ El archivo debe ser un script Lua (.lua) o de texto (.txt).', ephemeral: true });
        }

        await interaction.deferReply();

        try {
            const response = await fetch(attachment.url);
            const obfuscatedCode = await response.text();

            const decryptedCode = deobfuscate(obfuscatedCode);

            const tempFilePath = path.join(__dirname, 'decrypted.lua');
            fs.writeFileSync(tempFilePath, decryptedCode, 'utf-8');

            const fileAttachment = new AttachmentBuilder(tempFilePath, { name: 'decrypted.lua' });

            await interaction.editReply({ 
                content: '✅ ¡Archivo deobfuscado correctamente!', 
                files: [fileAttachment] 
            });

            fs.unlinkSync(tempFilePath);

        } catch (error) {
            console.error(error);
            await interaction.editReply({ content: `❌ Error al deobfuscar: ${error.message}` });
        }
    }
});

client.login(token);
