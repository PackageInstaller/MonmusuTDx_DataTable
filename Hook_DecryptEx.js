var dumpCounter = 0;

function get_self_process_name() {
  var openPtr = Module.getExportByName('libc.so', 'open');
  var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

  var readPtr = Module.getExportByName("libc.so", "read");
  var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

  var closePtr = Module.getExportByName('libc.so', 'close');
  var close = new NativeFunction(closePtr, 'int', ['int']);

  var path = Memory.allocUtf8String("/proc/self/cmdline");
  var fd = open(path, 0);
  if (fd != -1) {
    var buffer = Memory.alloc(0x1000);
    var result = read(fd, buffer, 0x1000);
    close(fd);
    result = ptr(buffer).readCString();
    return result;
  }
  return "-1";
}

var intervalId = setInterval(function () {
  var il2cppModule = Process.findModuleByName('libil2cpp.so');
  if (il2cppModule) {
    clearInterval(intervalId);
    console.log('IL2CPP 基地址:', il2cppModule.base);
    var rva = 0x1A6C140; // cLightCoder__DecryptEx
    var va = il2cppModule.base.add(rva);

    Interceptor.attach(va, {
      onLeave: function (retval) {
        const outputBinDataPtr = retval;
        try {
          const outputByteLength = outputBinDataPtr.add(0x18).readInt();
          const outputByteData = outputBinDataPtr.add(0x20).readByteArray(outputByteLength);

          var packageName = get_self_process_name();
          var filePath = "/data/data/" + packageName + "/dec_ab_" + dumpCounter + ".bundle";
          dumpCounter++;

          var file = new File(filePath, "wb");
          file.write(outputByteData);
          file.flush();
          file.close();
          console.log("保存到: " + filePath + " (长度: " + outputByteLength + " bytes)");

        } catch (e) {
          console.error("处理或保存解密后输出 binData 时出错:", e);
          if (e.stack) {
            console.error("错误堆栈:", e.stack);
          }
        }
      },
    });
  }
}, 200);

