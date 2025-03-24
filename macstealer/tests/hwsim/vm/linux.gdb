python
import os, subprocess
kdir = os.environ['KERNELDIR']
mdir = os.environ['MODULEDIR'] or '/lib/modules'
gdb.execute(f'add-auto-load-safe-path {kdir}/scripts/gdb/')
cwd=os.getcwd()
gdb.execute(f'cd {kdir}')
gdb.execute(f'source {kdir}/vmlinux-gdb.py')
p = subprocess.run([f'./linux', '--version'], capture_output=True)
ver = p.stdout.strip().decode('ascii')
gdb.execute(f'cd {cwd}')
end
break os_early_checks
commands
silent
python
gdb.execute(f'cd {kdir}')
gdb.execute(f'lx-symbols {mdir}/{ver}/')
gdb.execute(f'cd {cwd}')
end
# only once
del 1
continue
end
handle 11 nostop noprint pass
#
# So ... this is complicated. When gdb installs a regular breakpoint
# on some place, it writes there a breakpoint instruction (which is
# a single 0xCC byte on x86). This breaks out into the debugger and
# it can then restart/simulate the correct instruction when continuing
# across the breakpoint.
#
# Additionally, gdb (correctly) removes these breakpoint instructions
# from forked children when detaching from them. This also seems fine.
#
# However, due to how user-mode-linux works, this causes issues with
# kernel modules. These are loaded into the vmalloc area, and even if
# that isn't quite part of physmem, it's still mapped as MAP_SHARED.
#
# Unfortunately, this means that gdb deletes breakpoints in modules
# when a new userspace process is started, since that causes a new
# process to be created by clone() and gdb has to detach from it.
#
# The other thing to know is that when gdb hits a breakpoint it will
# restore all the code to normal, and reinstall breakpoints when we
# continue.
#
# Thus we can use that behaviour to work around the module issue:
# simply put a breakpoint on init_new_ldt which happens just after
# the clone() for a new userspace process, and do nothing there but
# continue, which reinstalls all breakpoints, including the ones in
# modules.
#
break init_new_ldt
commands
silent
continue
end

echo \n
echo Welcome to hwsim kernel debugging\n
echo ---------------------------------\n\n
echo You can install breakpoints in modules, they're treated\n
echo as shared libraries, so just say 'y' if asked to make the\n
echo breakpoint pending on future load.\n\n
echo Do NOT, however, delete the breakpoint on 'init_new_ldt'!\n\n
echo Now enter 'run' to start the run.\n\n
echo Have fun!\n\n
