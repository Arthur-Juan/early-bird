# 1. Lê os bytes da DLL local
$dllPath = "C:\Users\Arthur\Documents\crow\dll-indirect-syscalls\target\release\indirect_dll.dll"
$bytes = [System.IO.File]::ReadAllBytes($dllPath)

# 2. Carrega a DLL como Assembly em memória
$assem = [System.Reflection.Assembly]::Load($bytes)

# 3. Busca a classe com a função exportada
# (se não usou um namespace, o nome da classe será o nome do crate com a 1ª letra maiúscula)
$class = $assem.GetType("Indirect_dll")  # ajuste aqui se o nome for diferente

# 4. Busca o método RunMain
$method = $class.GetMethod("RunMain")

# 5. Invoca o método, simulando um rundll32
$method.Invoke(0, @([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 0))
