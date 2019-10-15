from threading import Semaphore
from functools import partial

from openvas_lib import VulnscanManager, VulnscanException


def my_print_status(i):
    print(str(i))


def my_launch_scanner():
    sem = Semaphore(0)
    #
    # # Configure
    manager = VulnscanManager("localhost", "admin", "123456")

    # Launch
    scan_id, target_id = manager.launch_scan('192.168.86.12',
                                             profile="Full and fast",
                                             callback_end=partial(lambda x: x.release(), sem),
                                             callback_progress=my_print_status)
    print(scan_id)
    sem.acquire()
    res = manager.get_results(scan_id)
    for flag in res:
        print('------------------------------------------------------------------------------------------------------------')
        # print('impact:' + flag.impact + '  summary:' + flag.summary + '  vulnerability:' + flag.vulnerability_insight)
        print('vulnerability:' + str(flag.vulnerability_insight) + '  affected_software:' + str(flag.affected_software) + '  notes:' + str(flag.notes))
        print('raw_description:' + str(flag.raw_description) + '  overrides:' + str(flag.overrides))
        print('port:' + str(flag.port) + '  threat:' + str(flag.threat) + '  severity:' + str(flag.severity))
        print('nvt_name:' + str(flag.nvt.name) + '  cvss_base_vector:' + str(flag.nvt.cvss_base_vector) + '  cvss_base:' + str(flag.nvt.cvss_base))
        print('risk_factor' + str(flag.nvt.risk_factor) + '  summary:' + str(flag.nvt.summary) + '  description:' + str(flag.nvt.description))
        print('family:'+ str(flag.nvt.family) + '  category:'+ str(flag.nvt.category) + '  cve:'+str(flag.nvt.cve))
        print('bugtrap: ' + str(flag.nvt.bugtraq) + '  xrefs:' + str(flag.nvt.xrefs) + 'fingerprints:' + str(flag.nvt.fingerprints))
        print('---------------------------------------------------------------------------------------------------------')
    # Finished scan
    print("finished")


my_launch_scanner()
