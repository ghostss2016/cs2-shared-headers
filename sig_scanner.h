#pragma once
// sig_scanner.h — рантайм сигнатурный сканер для CS2 MM:S плагинов (self-contained, без CModule/gamedata-машинерии).
// Единый центральный заголовок (цепочка: ghostss2016/cs2-gamedata). Плагины: #include "sig_scanner.h".
// Паттерн вида "55 48 ? 89" (? = wildcard). Подтверждён лабой (dl_iterate_phdr + скан PT_LOAD PF_X).
#include <link.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstddef>

namespace SigScan
{
	// Найти паттерн в executable-сегменте модуля (moduleSubstr — подстрока dlpi_name, напр. "libserver.so").
	// pCount != nullptr -> запишет число совпадений (для safe-disable при 0 или >1).
	inline uintptr_t Find(const char* moduleSubstr, const char* pattern, int* pCount = nullptr)
	{
		struct D { const char* n; uintptr_t addr; size_t size; } d{ moduleSubstr, 0, 0 };
		dl_iterate_phdr([](dl_phdr_info* info, size_t, void* p) -> int {
			D* dd = reinterpret_cast<D*>(p);
			if (info->dlpi_name && std::strstr(info->dlpi_name, dd->n)) {
				for (int k = 0; k < info->dlpi_phnum; k++) {
					const ElfW(Phdr)& ph = info->dlpi_phdr[k];
					if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
						dd->addr = info->dlpi_addr + ph.p_vaddr; dd->size = ph.p_memsz; return 0;
					}
				}
			}
			return 0;
		}, &d);
		if (pCount) *pCount = 0;
		if (!d.addr) return 0;

		unsigned char bytes[512]; char mask[512]; size_t len = 0;
		for (const char* c = pattern; *c && len < 512; ) {
			if (*c == ' ') { c++; continue; }
			if (*c == '?') { mask[len] = '?'; bytes[len] = 0; len++; c++; if (*c == '?') c++; }
			else { bytes[len] = (unsigned char)strtol(c, nullptr, 16); mask[len] = 'x'; len++; c += 2; }
		}
		unsigned char* base = reinterpret_cast<unsigned char*>(d.addr);
		uintptr_t first = 0; int cnt = 0;
		for (size_t o = 0; o + len <= d.size; o++) {
			bool m = true;
			for (size_t j = 0; j < len; j++) if (mask[j] == 'x' && base[o + j] != bytes[j]) { m = false; break; }
			if (m) { if (!first) first = reinterpret_cast<uintptr_t>(base + o); cnt++; if (pCount && cnt > 1) break; }
		}
		if (pCount) *pCount = cnt;
		return (cnt == 1 || !pCount) ? first : (cnt >= 1 ? first : 0);
	}

	// Резолв в указатель функции. Возвращает nullptr при 0 или >1 совпадений (safe-disable).
	// logf опционален: void logf(const char* fmt, ...) — плагин передаёт ConMsg.
	template<class Fn>
	inline Fn Resolve(const char* module, const char* pattern, const char* name, void(*logf)(const char*, ...) = nullptr)
	{
		int cnt = 0;
		uintptr_t a = Find(module, pattern, &cnt);
		if (logf) logf("[sig] %s: matches=%d addr=%p\n", name, cnt, (void*)a);
		return (cnt == 1) ? reinterpret_cast<Fn>(a) : nullptr;
	}
}
