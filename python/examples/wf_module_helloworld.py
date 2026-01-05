"""Module Workflow hello world."""
import json

from binaryninja.log import Logger
from binaryninja.workflow import Workflow, Activity, AnalysisContext

log = Logger(0, 'WorkflowHelloWorld')


def do_action(context: AnalysisContext):
    """Do stuff in main workflow action."""
    bv = context.view
    log.session_id = bv.file.session_id
    bv.add_tag(bv.entry_point, 'Needs Analysis', 'Hello World!')
    log.log_info('Added Hello World Tag')


wf = Workflow('core.module.metaAnalysis').clone('plugin.module.HelloWorld')

wf.register_activity(Activity(
    configuration=json.dumps({
        'name': 'analysis.helloworld',
        'title': 'Tag Entry Point',
        'description': 'Tag the entry point with "Hello World!".',
        'eligibility': {
            'runOnce': True
        },
        'dependencies': {
            'downstream': ['core.module.update']
        }
    }),
    action=do_action
))

wf.insert('core.module.finishUpdate', ['analysis.helloworld'])
wf.register()
