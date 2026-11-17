import hashlib
import math
import random
import string
import urllib.request
import streamlit as st

# Configuración de la página
st.set_page_config(
    page_title="SecurPass Analyzer", page_icon="🔐", layout="centered"
)


def calcular_entropia(password):
  """Calcula la entropía en bits de una contraseña y su espacio de caracteres (R)."""
  if not password:
    return 0, 0

  tiene_minuscula = any(c in string.ascii_lowercase for c in password)
  tiene_mayuscula = any(c in string.ascii_uppercase for c in password)
  tiene_numero = any(c in string.digits for c in password)
  tiene_simbolo = any(c in string.punctuation for c in password)

  rango_caracteres = 0
  if tiene_minuscula:
    rango_caracteres += 26
  if tiene_mayuscula:
    rango_caracteres += 26
  if tiene_numero:
    rango_caracteres += 10
  if tiene_simbolo:
    rango_caracteres += 33

  if rango_caracteres == 0:
    return 0, 0

  longitud = len(password)
  entropia = longitud * math.log2(rango_caracteres)
  return round(entropia, 2), rango_caracteres


def estimar_tiempo_fuerza_bruta(entropia):
  """Estima el tiempo que tardaría una GPU moderna en descifrarla."""
  if entropia == 0:
    return "Instantáneo"

  combinaciones = 2**entropia
  intentos_por_segundo = 10**10
  segundos = combinaciones / intentos_por_segundo

  minutos = segundos / 60
  horas = minutos / 60
  dias = horas / 24
  anos = dias / 365

  if anos > 1_000_000:
    return "Millones de años (Prácticamente Imposible)"
  elif anos > 1:
    return f"Aprox. {int(anos):,} años"
  elif dias > 1:
    return f"Aprox. {int(dias)} días"
  elif horas > 1:
    return f"Aprox. {int(horas)} horas"
  elif minutos > 1:
    return f"Aprox. {int(minutos)} minutos"
  else:
    return "Menos de un segundo"


def verificar_filtracion(password):
  """Verifica si la contraseña ha sido filtrada usando k-Anonymity y HaveIBeenPwned."""
  if not password:
    return 0

  # Convertir contraseña a hash SHA-1 en mayúsculas
  sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
  prefix = sha1_password[:5]
  suffix = sha1_password[5:]

  url = f"https://api.pwnedpasswords.com/range/{prefix}"
  try:
    req = urllib.request.Request(
        url, headers={"User-Agent": "SecurPass-Student-App"}
    )
    with urllib.request.urlopen(req) as response:
      body = response.read().decode("utf-8")
      for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
          return int(count)
  except Exception:
    return -1

  return 0


def generar_contrasena(
    longitud, usar_mayus, usar_minus, usar_nums, usar_simbolos
):
  """Genera una contraseña basándose en las opciones seleccionadas."""
  pool = ""
  if usar_minus:
    pool += string.ascii_lowercase
  if usar_mayus:
    pool += string.ascii_uppercase
  if usar_nums:
    pool += string.digits
  if usar_simbolos:
    pool += string.punctuation

  if not pool:
    return None

  return "".join(random.choice(pool) for _ in range(longitud))


# Interfaz de Usuario con Streamlit
st.title("🔐 SecurPass: Generador y Validador con Entropía")
st.write(
    "Herramienta profesional de análisis criptográfico y verificación de"
    " brechas."
)

tab1, tab2 = st.tabs(["🔍 Analizar Contraseña", "⚡ Generador Seguro"])

with tab1:
  st.subheader("Evaluador de Complejidad y Brechas")
  pwd_usuario = st.text_input(
      "Ingresa una contraseña para analizar:", type="password"
  )

  if pwd_usuario:
    entropia, pool = calcular_entropia(pwd_usuario)
    tiempo = estimar_tiempo_fuerza_bruta(entropia)

    col1, col2 = st.columns(2)
    col1.metric("Entropía Calculada", f"{entropia} bits")
    col2.metric("Espacio de Caracteres (R)", f"{pool} opciones")

    st.write(f"⏱️ **Tiempo estimado de descifrado (GPU):** {tiempo}")

    if entropia >= 60:
      st.success("✅ **Contraseña Fuerte:** Excelente nivel de seguridad.")
    elif entropia >= 40:
      st.warning(
          "⚠️ **Contraseña Moderada:** Podría ser más robusta aumentando su"
          " longitud."
      )
    else:
      st.error(
          "❌ **Contraseña Débil:** Vulnerable a ataques de fuerza bruta"
          " rápidos."
      )

    st.markdown("---")
    st.subheader("🌐 Verificación en Bases de Datos de Brechas")
    st.write(
        "Haz clic en el botón para consultar si esta clave ha sido expuesta"
        " públicamente en internet (usando *k-Anonymity* para total"
        " privacidad)."
    )

    if st.button("Verificar si fue filtrada"):
      with st.spinner("Consultando bases de datos de forma segura..."):
        filtraciones = verificar_filtracion(pwd_usuario)

      if filtraciones == -1:
        st.warning(
            "⚠️ No se pudo conectar con el servidor (verifica tu conexión a"
            " internet)."
        )
      elif filtraciones > 0:
        st.error(
            f"🚨 **¡CONTRASEÑA COMPROMETIDA!** Esta contraseña ha aparecido en"
            f" **{filtraciones:,}** filtraciones de datos públicas. ¡No la"
            " utilices!"
        )
      else:
        st.success(
            "🔒 **¡Limpia!** Esta contraseña no aparece en ninguna filtración"
            " conocida."
        )

with tab2:
  st.subheader("Generador de Alta Entropía con Filtros")
  longitud_slider = st.slider("Longitud de la contraseña", 6, 32, 16)

  st.write("Personaliza los conjuntos de caracteres permitidos:")
  col_c1, col_c2 = st.columns(2)
  with col_c1:
    inc_mayus = st.checkbox("Incluir mayúsculas (A-Z)", value=True)
    inc_minus = st.checkbox("Incluir minúsculas (a-z)", value=True)
  with col_c2:
    inc_nums = st.checkbox("Incluir números (0-9)", value=True)
    inc_simbolos = st.checkbox("Incluir símbolos (!@#$)", value=True)

  if st.button("Generar Contraseña Robusta"):
    nueva_pwd = generar_contrasena(
        longitud_slider, inc_mayus, inc_minus, inc_nums, inc_simbolos
    )

    if nueva_pwd is None:
      st.error(
          "❌ Debes seleccionar al menos un tipo de caracter para generar la"
          " contraseña."
      )
    else:
      ent_gen, _ = calcular_entropia(nueva_pwd)
      st.code(nueva_pwd, language="")
      st.info(
          f"Esta contraseña generada tiene una entropía de **{ent_gen} bits** y"
          f" tardaría **{estimar_tiempo_fuerza_bruta(ent_gen)}** en ser"
          " descifrada."
      )
      st.toast("¡Contraseña generada con éxito! 🎉", icon="🚀")