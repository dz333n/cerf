/* Window thunks: Get/SetWindowLong, text, rect ops */
#include "win32_thunks.h"
#include <cstdio>

void Win32Thunks::RegisterWindowPropsHandlers() {
    Thunk("SetRect", 103, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        mem.Write32(regs[0], regs[1]); mem.Write32(regs[0]+4, regs[2]);
        mem.Write32(regs[0]+8, regs[3]); mem.Write32(regs[0]+12, ReadStackArg(regs,mem,0));
        regs[0] = 1; return true;
    });
    Thunk("CopyRect", 96, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i=0;i<4;i++) mem.Write32(regs[0]+i*4, mem.Read32(regs[1]+i*4));
        regs[0] = 1; return true;
    });
    Thunk("SetRectEmpty", 104, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i=0;i<4;i++) mem.Write32(regs[0]+i*4, 0); regs[0] = 1; return true;
    });
    Thunk("InflateRect", 98, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]),t=mem.Read32(regs[0]+4),r=mem.Read32(regs[0]+8),b=mem.Read32(regs[0]+12);
        int32_t dx=(int32_t)regs[1],dy=(int32_t)regs[2];
        mem.Write32(regs[0],l-dx); mem.Write32(regs[0]+4,t-dy); mem.Write32(regs[0]+8,r+dx); mem.Write32(regs[0]+12,b+dy);
        regs[0]=1; return true;
    });
    Thunk("OffsetRect", 101, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        OffsetRect(&rc,(int)regs[1],(int)regs[2]);
        mem.Write32(regs[0],rc.left); mem.Write32(regs[0]+4,rc.top);
        mem.Write32(regs[0]+8,rc.right); mem.Write32(regs[0]+12,rc.bottom);
        regs[0]=1; return true;
    });
    Thunk("IntersectRect", 99, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT a,b,out;
        a.left=mem.Read32(regs[1]); a.top=mem.Read32(regs[1]+4); a.right=mem.Read32(regs[1]+8); a.bottom=mem.Read32(regs[1]+12);
        b.left=mem.Read32(regs[2]); b.top=mem.Read32(regs[2]+4); b.right=mem.Read32(regs[2]+8); b.bottom=mem.Read32(regs[2]+12);
        BOOL ret = IntersectRect(&out,&a,&b);
        mem.Write32(regs[0],out.left); mem.Write32(regs[0]+4,out.top);
        mem.Write32(regs[0]+8,out.right); mem.Write32(regs[0]+12,out.bottom);
        regs[0]=ret; return true;
    });
    Thunk("UnionRect", 106, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT a,b,out;
        a.left=mem.Read32(regs[1]); a.top=mem.Read32(regs[1]+4); a.right=mem.Read32(regs[1]+8); a.bottom=mem.Read32(regs[1]+12);
        b.left=mem.Read32(regs[2]); b.top=mem.Read32(regs[2]+4); b.right=mem.Read32(regs[2]+8); b.bottom=mem.Read32(regs[2]+12);
        BOOL ret = UnionRect(&out,&a,&b);
        mem.Write32(regs[0],out.left); mem.Write32(regs[0]+4,out.top); mem.Write32(regs[0]+8,out.right); mem.Write32(regs[0]+12,out.bottom);
        regs[0]=ret; return true;
    });
    Thunk("PtInRect", 102, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        POINT pt={(LONG)regs[1],(LONG)regs[2]}; regs[0]=PtInRect(&rc,pt); return true;
    });
    Thunk("IsRectEmpty", 100, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]),t=mem.Read32(regs[0]+4),r=mem.Read32(regs[0]+8),b=mem.Read32(regs[0]+12);
        regs[0]=(r<=l||b<=t)?1:0; return true;
    });
    Thunk("EqualRect", 97, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        bool eq=true; for(int i=0;i<4;i++) if(mem.Read32(regs[0]+i*4)!=mem.Read32(regs[1]+i*4)) eq=false;
        regs[0]=eq?1:0; return true;
    });
    Thunk("SubtractRect", 105, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=0; return true; });
    Thunk("GetWindowRect", 248, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; BOOL ret=GetWindowRect((HWND)(intptr_t)(int32_t)regs[0],&rc);
        mem.Write32(regs[1],rc.left); mem.Write32(regs[1]+4,rc.top);
        mem.Write32(regs[1]+8,rc.right); mem.Write32(regs[1]+12,rc.bottom);
        regs[0]=ret; return true;
    });
    Thunk("GetClientRect", 249, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; BOOL ret=GetClientRect((HWND)(intptr_t)(int32_t)regs[0],&rc);
        mem.Write32(regs[1],rc.left); mem.Write32(regs[1]+4,rc.top);
        mem.Write32(regs[1]+8,rc.right); mem.Write32(regs[1]+12,rc.bottom);
        regs[0]=ret; return true;
    });
    Thunk("InvalidateRect", 250, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT*prc=NULL; RECT rc;
        if(regs[1]){rc.left=mem.Read32(regs[1]);rc.top=mem.Read32(regs[1]+4);rc.right=mem.Read32(regs[1]+8);rc.bottom=mem.Read32(regs[1]+12);prc=&rc;}
        regs[0]=InvalidateRect((HWND)(intptr_t)(int32_t)regs[0],prc,regs[2]); return true;
    });
    Thunk("ValidateRect", 278, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=ValidateRect((HWND)(intptr_t)(int32_t)regs[0],NULL); return true; });
    Thunk("GetUpdateRect", 274, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; BOOL ret=GetUpdateRect((HWND)(intptr_t)(int32_t)regs[0],&rc,regs[2]);
        if(regs[1]){mem.Write32(regs[1],rc.left);mem.Write32(regs[1]+4,rc.top);mem.Write32(regs[1]+8,rc.right);mem.Write32(regs[1]+12,rc.bottom);}
        regs[0]=ret; return true;
    });
    Thunk("GetParent", 269, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=(uint32_t)(uintptr_t)GetParent((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("IsWindow", 271, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=IsWindow((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("IsWindowVisible", 886, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=IsWindowVisible((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("EnableWindow", 287, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=EnableWindow((HWND)(intptr_t)(int32_t)regs[0],regs[1]); return true; });
    Thunk("IsWindowEnabled", 288, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=IsWindowEnabled((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("SetWindowTextW", 256, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0]=SetWindowTextW((HWND)(intptr_t)(int32_t)regs[0], ReadWStringFromEmu(mem,regs[1]).c_str()); return true;
    });
    Thunk("GetWindowLongW", 259, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=GetWindowLongW((HWND)(intptr_t)(int32_t)regs[0],(int)regs[1]); return true; });
    Thunk("SetWindowLongW", 258, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LONG nv=(LONG)regs[2]; if((int)regs[1]==GWL_EXSTYLE) nv&=0x0FFFFFFF;
        regs[0]=SetWindowLongW((HWND)(intptr_t)(int32_t)regs[0],(int)regs[1],nv); return true;
    });
    Thunk("GetWindowTextW", 257, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[1024]={}; uint32_t mx=regs[2]; if(mx>1024)mx=1024;
        int ret=GetWindowTextW((HWND)(intptr_t)(int32_t)regs[0],buf,mx);
        for(int i=0;i<=ret;i++) mem.Write16(regs[1]+i*2,buf[i]);
        regs[0]=ret; return true;
    });
    Thunk("GetWindowTextLengthW", 276, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0]=GetWindowTextLengthW((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("IsChild", 277, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0]=IsChild((HWND)(intptr_t)(int32_t)regs[0],(HWND)(intptr_t)(int32_t)regs[1]); return true;
    });
    Thunk("AdjustWindowRectEx", 887, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        BOOL ret=AdjustWindowRectEx(&rc,regs[1],regs[2],regs[3]);
        mem.Write32(regs[0],rc.left); mem.Write32(regs[0]+4,rc.top);
        mem.Write32(regs[0]+8,rc.right); mem.Write32(regs[0]+12,rc.bottom);
        regs[0]=ret; return true;
    });
}
