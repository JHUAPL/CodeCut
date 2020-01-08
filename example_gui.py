
import idc
import ida_kernwin

import imp
import snap_cg

import lfa
import maxcut
import module
import cc_base
import modnaming
import basicutils_7x as basicutils

from PyQt5 import QtCore, QtGui, QtWidgets

#-------------------------------------------------------------------------------
def handler(item, column_no):
  ea = item.ea
  if is_mapped(ea):
    jumpto(ea)

#-------------------------------------------------------------------------------
class CBaseTreeViewer(ida_kernwin.PluginForm):
  def populate_tree(self):
    # Clear previous items
    self.tree.clear()

    #Do LFA and MaxCut Analysis to find module boundaries
    _, lfa_modlist = lfa.analyze()
    for module_data in lfa_modlist:
      module_name = "Module 0x%08x:0x%08x" % (module_data.start, module_data.end)
      item = QtWidgets.QTreeWidgetItem(self.tree)
      item.setText(0, module_name)
      item.ea = module_data.start

      for func in Functions(module_data.start, module_data.end):
        node = QtWidgets.QTreeWidgetItem(item)
        node.setText(0, "0x%08x: %s" % (func, idc.get_func_name(func)))
        node.ea = func

    self.tree.itemDoubleClicked.connect(handler)

  def OnCreate(self, form):
    # Get parent widget
    self.parent = ida_kernwin.PluginForm.FormToPyQtWidget(form)

    # Create tree control
    self.tree = QtWidgets.QTreeWidget()
    self.tree.setHeaderLabels(("Names",))
    self.tree.setColumnWidth(0, 100)

    # Create layout
    layout = QtWidgets.QVBoxLayout()
    layout.addWidget(self.tree)
    self.populate_tree()

    # Populate PluginForm
    self.parent.setLayout(layout)

  def Show(self, title):
    return ida_kernwin.PluginForm.Show(self, title, options = ida_kernwin.PluginForm.WOPN_PERSIST)

#-------------------------------------------------------------------------------
def main():
  tree_frm = CBaseTreeViewer()
  tree_frm.Show("Object Files")

if __name__ == "__main__":
  imp.reload(modnaming)
  imp.reload(module)
  imp.reload(cc_base)
  imp.reload(lfa)
  imp.reload(maxcut)
  imp.reload(snap_cg)
  imp.reload(basicutils)
  main()

