import sys
import setuptools
from wheel.bdist_wheel import bdist_wheel

if sys.platform == "win32":
    extra_compile_args = []
    libraries = ["libcrypto", "advapi32", "crypt32", "gdi32", "user32", "ws2_32"]
else:
    extra_compile_args = ["-std=c99"]
    libraries = ["crypto"]


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        if python.startswith("cp"):
            return "cp39", "abi3", plat

        return python, abi, plat


setuptools.setup(
    name="Hypic",
    version="0.1.0",
    author="Imine Belkacem",
    author_email="imine.belkacem@gmail.com",
    description="hypic is a post-quantum version of QUIC protocol",
    ext_modules=[
        setuptools.Extension(
            "Hypic._buffer",
            extra_compile_args=extra_compile_args,
            sources=["src/Hypic/_buffer.c"],
            define_macros=[("Py_LIMITED_API", "0x03080000")],
            py_limited_api=True,
        ),
        setuptools.Extension(
            "Hypic._crypto",
            extra_compile_args=extra_compile_args,
            libraries=libraries,
            sources=["src/Hypic/_crypto.c"],
            define_macros=[("Py_LIMITED_API", "0x03080000")],
            py_limited_api=True,
        ),
    ],
    cmdclass={"bdist_wheel": bdist_wheel_abi3},
)
