from .afl import AFL
import logging
import os
import subprocess

l = logging.getLogger("phuzzer.phuzzers.afl")


class EMS(AFL):
    """ EMS port of AFL phuzzer.
        Paper found here:
        https://nesa.zju.edu.cn/download/lcy_pdf_ems_ndss22.pdf
        Build found at https://github.com/g0kkk/bind
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def choose_afl(self):
        self.afl_bin_dir = '/phuzzers/EMS/' if 'AFL_PATH' not in os.environ else os.environ['AFL_PATH']
        afl_bin_path = os.path.join(self.afl_bin_dir, "afl-fuzz")
        return afl_bin_path

    def _start_afl_instance(self, instance_cnt=0):
        args, fuzzer_id = self.build_args()
        my_env = os.environ.copy()

        if "AFL_SET_AFFINITY" in my_env:
            l.warning("supported by custom built at https://github.com/g0kkk/bind")
            core_num = int(my_env["AFL_SET_AFFINITY"])
            core_num += instance_cnt
            args = [args[0]] + [f"-b {core_num}"] + ["-D"] + args[1:]
        else:
            # add bit flipping by default
            args = [args[0]] + ["-D"] + args[1:]

        self.log_command(args, fuzzer_id, my_env)

        logpath = os.path.join(self.work_dir, fuzzer_id + ".log")
        print("execing: %s > %s", ' '.join(args), logpath)
        l.warning("execing: %s > %s", ' '.join(args), logpath)

        scr_fn = os.path.join(self.work_dir, f"fuzz-{instance_cnt}.sh")
        with open(scr_fn, "w") as scr:
            scr.write("#! /bin/bash \n")
            for key, val in my_env.items():
                scr.write(f'export {key}="{val}"\n')
            scr.write(" ".join(args) + "\n")
        print(f"Fuzz command written out to {scr_fn}")

        os.chmod(scr_fn, mode=0o774)

        with open(logpath, "w") as fp:
            return subprocess.Popen([scr_fn], stdout=fp, stderr=fp, close_fds=True)
