"""
IDA Stack Frame Viewer Plugin
Double-click cells to jump to addresses
Hotkey: Ctrl+Shift+K
"""

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_dbg
import ida_ida
import ida_name
import idc

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
except:
    from PySide6 import QtWidgets, QtCore, QtGui

# Colors
COLOR_SHADOW = QtGui.QColor(255, 224, 176)
COLOR_RETADDR = QtGui.QColor(255, 176, 176)
COLOR_HEADER = QtGui.QColor(220, 220, 220)


class StackViewerDebugHook(ida_dbg.DBG_Hooks):
    """Debugger hook for auto-refresh when debugger suspends"""

    def __init__(self, viewer):
        super(StackViewerDebugHook, self).__init__()
        self.viewer = viewer

    def dbg_suspend_process(self):
        """Called when debugger suspends (breakpoint, step, pause, etc)"""
        try:
            self.viewer.update_view()
        except:
            pass
        return 0

    def dbg_step_into(self):
        """Called after step into (F7)"""
        try:
            self.viewer.update_view()
        except:
            pass
        return 0

    def dbg_step_over(self):
        """Called after step over (F8)"""
        try:
            self.viewer.update_view()
        except:
            pass
        return 0

    def dbg_step_until_ret(self):
        """Called after step out"""
        try:
            self.viewer.update_view()
        except:
            pass
        return 0


class SimpleStackViewer(ida_kernwin.PluginForm):
    """Simple Stack Frame Viewer"""

    def __init__(self):
        super(SimpleStackViewer, self).__init__()
        self.collapsed_sections = set()  # Track collapsed section rows
        self.dbg_hook = None  # Debugger hook

    def OnCreate(self, form):
        """Create widget"""
        self.parent = self.FormToPyQtWidget(form)
        self._setup_ui()

        # Register debugger hook for auto-refresh
        self.dbg_hook = StackViewerDebugHook(self)
        self.dbg_hook.hook()

    def _setup_ui(self):
        """Setup UI"""
        layout = QtWidgets.QVBoxLayout()

        # Toolbar
        toolbar = QtWidgets.QHBoxLayout()

        self.addr_label = QtWidgets.QLabel("Ready")
        self.addr_label.setStyleSheet("font-weight: bold; color: #0066cc;")
        toolbar.addWidget(self.addr_label)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Table
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            ['Offset', 'Address', 'Name', 'Value'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)  # Read-only
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)  # Select full row

        # Set monospace font like IDA
        mono_font = QtGui.QFont("Consolas", 9)
        if not mono_font.exactMatch():
            mono_font = QtGui.QFont("Courier New", 9)
        self.table.setFont(mono_font)

        # Column widths
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 140)  # Address column - fit 16 hex digits
        self.table.setColumnWidth(2, 200)

        # Connect events
        self.table.cellDoubleClicked.connect(self._on_cell_clicked)
        self.table.cellClicked.connect(
            self._on_cell_single_clicked)  # For collapse/expand
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)

        layout.addWidget(self.table)

        self.parent.setLayout(layout)

        # Initial view
        self.update_view()

    def update_view(self):
        """Update stack view"""
        try:
            ea = idc.here()
            func = ida_funcs.get_func(ea)

            if not func:
                self.addr_label.setText("❌ Not in a function")
                self.table.setRowCount(0)
                return

            # Get current RSP for highlighting
            current_rsp = self._get_rsp()

            # Get full call stack
            call_stack = self._get_call_stack(ea)
            self.addr_label.setText(f"📊 Call Stack ({len(call_stack)} frames)")

            # Analyze entire call stack
            items = self._analyze_call_stack(call_stack)

            # Store items for collapse tracking
            self.items = items

            # Display
            self.table.setRowCount(len(items))

            for row, item in enumerate(items):
                # Check if this row's address matches current RSP
                is_rsp_row = False
                if current_rsp and len(item['values']) > 1:
                    try:
                        addr_str = item['values'][1]
                        if addr_str:
                            addr = int(addr_str, 16)
                            if addr == current_rsp:
                                is_rsp_row = True
                    except:
                        pass

                # Check if this is a header row that should span columns
                if item.get('is_section_header') or item.get('is_frame_header'):
                    # Span entire row for headers
                    name_text = item['values'][2]
                    desc_text = item['values'][4] if len(
                        item['values']) > 4 else ''

                    # Combine name and description
                    combined_text = name_text
                    if desc_text:
                        combined_text = f"{name_text}    {desc_text}"

                    # Create merged cell spanning all 4 columns
                    cell = QtWidgets.QTableWidgetItem(combined_text)
                    cell.setBackground(item['color'])
                    if item.get('bold'):
                        font = cell.font()
                        font.setBold(True)
                        cell.setFont(font)
                    self.table.setItem(row, 0, cell)
                    self.table.setSpan(row, 0, 1, 4)  # Span all 4 columns
                else:
                    # Normal row - fill columns, merge value with description
                    for col in range(min(4, len(item['values']))):
                        if col == 3:  # Value column - merge with description
                            value_text = item['values'][3]
                            desc_text = item['values'][4] if len(
                                item['values']) > 4 and item['values'][4] else ''
                            # Combine value and description
                            if desc_text:
                                combined = f"{value_text}    {desc_text}"
                            else:
                                combined = value_text
                            cell = QtWidgets.QTableWidgetItem(combined)
                        else:
                            cell = QtWidgets.QTableWidgetItem(
                                item['values'][col])

                        # Highlight RSP row with bright yellow
                        if is_rsp_row:
                            # Bright yellow for RSP
                            cell.setBackground(QtGui.QColor(255, 255, 0))
                            font = cell.font()
                            font.setBold(True)
                            cell.setFont(font)
                        else:
                            cell.setBackground(item['color'])
                            if item.get('bold'):
                                font = cell.font()
                                font.setBold(True)
                                cell.setFont(font)
                        self.table.setItem(row, col, cell)

                # Apply collapsed state
                if item.get('hidden'):
                    self.table.setRowHidden(row, True)

        except Exception as e:
            self.addr_label.setText(f"❌ Error: {e}")

    def _analyze(self, func, name):
        """Analyze stack - detailed view with values"""
        items = []

        # Get stack size and RSP
        stack_size = self._get_stack_size(func)
        is_64 = self._is_64bit()

        # Try to get RSP value if debugger active
        rsp_value = self._get_rsp()

        # Header
        items.append({
            'values': ['', '', f'═══ {name} ═══', '', f'Stack: {stack_size:#x} bytes'],
            'color': COLOR_HEADER,
            'bold': True
        })

        if is_64:
            # Shadow Space Header
            items.append({
                'values': ['', '', '▼ Shadow Space (0x20 bytes)', '', 'Win64 calling convention'],
                'color': QtGui.QColor(200, 200, 200),
                'bold': True
            })

            for i, reg in enumerate(['RCX', 'RDX', 'R8', 'R9']):
                off = stack_size + 0x20 + (i * 8)
                value = self._read_qword(rsp_value + off) if rsp_value else ''
                items.append({
                    'values': [f'RSP+{off:#x}', '0x8', f'{reg} home', value, self._describe_value(value)],
                    'color': COLOR_SHADOW,
                    'bold': False
                })

        # Return Address
        items.append({
            'values': ['', '', '▼ Return Address', '', ''],
            'color': QtGui.QColor(200, 200, 200),
            'bold': True
        })

        ret_off = stack_size
        ret_value = self._read_qword(rsp_value + ret_off) if rsp_value else ''
        items.append({
            'values': [f'RSP+{ret_off:#x}', '0x8', 'Return RIP', ret_value, self._describe_value(ret_value)],
            'color': COLOR_RETADDR,
            'bold': False
        })

        # Stack Frame
        if stack_size > 0:
            items.append({
                'values': ['', '', f'▼ Stack Frame ({stack_size:#x} bytes)', '', ''],
                'color': QtGui.QColor(200, 200, 200),
                'bold': True
            })

            # Show each qword in stack
            offset = stack_size - 8
            qword_idx = 0

            while offset >= 0:
                value = self._read_qword(
                    rsp_value + offset) if rsp_value else ''
                items.append({
                    'values': [f'RSP+{offset:#x}', '0x8', f'var_{offset:X}', value, self._describe_value(value)],
                    'color': QtGui.QColor(220, 255, 220),
                    'bold': False
                })
                offset -= 8
                qword_idx += 1

        return items

    def _get_call_stack(self, current_ea):
        """Get full call stack"""
        frames = []

        # Try debugger call stack first
        if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
            try:
                rsp = idc.get_reg_value('RSP')
                rip = idc.get_reg_value('RIP')

                # Current frame
                func = ida_funcs.get_func(rip)
                if func:
                    frames.append({
                        'ea': rip,
                        'func': func,
                        'name': ida_funcs.get_func_name(func.start_ea),
                        'rsp': rsp
                    })

                # Walk stack to find return addresses
                current_rsp = rsp
                for i in range(20):  # Max 20 frames
                    # Get stack size of current function
                    if func:
                        stack_size = self._get_stack_size(func)
                        ret_addr_offset = current_rsp + stack_size

                        # Read return address
                        ret_addr = idc.get_qword(ret_addr_offset)
                        if ret_addr and ret_addr > 0x10000:
                            caller_func = ida_funcs.get_func(ret_addr)
                            if caller_func:
                                frames.append({
                                    'ea': ret_addr,
                                    'func': caller_func,
                                    'name': ida_funcs.get_func_name(caller_func.start_ea),
                                    'rsp': ret_addr_offset + 8
                                })
                                current_rsp = ret_addr_offset + 8
                                func = caller_func
                                continue
                    break

            except:
                pass

        # Fallback: just current function
        if not frames:
            func = ida_funcs.get_func(current_ea)
            if func:
                frames.append({
                    'ea': current_ea,
                    'func': func,
                    'name': ida_funcs.get_func_name(func.start_ea),
                    'rsp': None
                })

        return frames

    def _analyze_call_stack(self, call_stack):
        """Analyze entire call stack"""
        items = []
        is_64 = self._is_64bit()

        for frame_idx, frame in enumerate(call_stack):
            func = frame['func']
            name = frame['name']
            rsp_value = frame['rsp']  # Current RSP (after sub rsp)
            stack_size = self._get_stack_size(func)

            # Entry RSP = where RSP was when function was entered (before sub rsp)
            entry_rsp = rsp_value + stack_size if rsp_value else None

            # Calculate return address location from caller's RSP
            # Return address is at [caller_RSP - 8] because call pushes it
            ret_addr_location = None
            if frame_idx + 1 < len(call_stack):
                caller_rsp = call_stack[frame_idx + 1]['rsp']
                if caller_rsp:
                    ret_addr_location = caller_rsp - 8
            elif rsp_value:
                # For deepest frame, scan stack to find return address
                ret_addr_location = rsp_value + stack_size

            # Frame header
            depth_marker = '┃ ' * frame_idx + '▶ '
            items.append({
                'values': ['', '', f'{depth_marker}Frame #{frame_idx}: {name}', '', f'Stack: {stack_size:#x} bytes @ {frame["ea"]:#x}'],
                'color': COLOR_HEADER,
                'bold': True,
                'is_frame_header': True
            })

            if is_64:
                # Shadow Space - at [entry_RSP+8], [entry_RSP+0x10], [entry_RSP+0x18], [entry_RSP+0x20]
                # entry_RSP is where RSP was when function entered (before sub rsp)
                items.append({
                    'values': ['', '', '  ▼ Shadow Space', '', ''],
                    'color': QtGui.QColor(220, 220, 220),
                    'bold': True,
                    'is_section_header': True,
                    'section_id': f'shadow_{frame_idx}'
                })

                for i, reg in enumerate(['RCX', 'RDX', 'R8', 'R9']):
                    off = 8 + (i * 8)  # +8, +0x10, +0x18, +0x20
                    addr = entry_rsp + off if entry_rsp else 0
                    addr_str = f'{addr:016X}' if addr else ''
                    value_str, chain = self._read_qword(
                        addr) if addr else ('', [])
                    desc = self._get_addr_info(chain[0]) if chain else ''

                    # Calculate offset from current RSP for display
                    rsp_offset = (
                        addr - rsp_value) if (rsp_value and addr) else 0
                    offset_str = f'RSP+{rsp_offset:#x}' if rsp_offset >= 0 else f'RSP{rsp_offset:#x}'

                    items.append({
                        'values': [offset_str, addr_str, f'    {reg}', value_str, desc],
                        'color': COLOR_SHADOW,
                        'bold': False,
                        'section_id': f'shadow_{frame_idx}'
                    })

            # Return Address - at [entry_RSP] (where call instruction pushed it)
            items.append({
                'values': ['', '', '  ▼ Return Address', '', ''],
                'color': QtGui.QColor(220, 220, 220),
                'bold': True,
                'is_section_header': True,
                'section_id': f'return_{frame_idx}'
            })

            if entry_rsp:
                # Return address is at entry_RSP (top of stack when function entered)
                ret_addr_str = f'{entry_rsp:016X}'
                ret_value_str, ret_chain = self._read_qword(
                    entry_rsp) if rsp_value else ('', [])
                ret_desc = self._get_addr_info(
                    ret_chain[0]) if ret_chain else ''

                # Calculate offset from current RSP
                ret_off = entry_rsp - rsp_value if rsp_value else 0
                offset_str = f'RSP+{ret_off:#x}' if ret_off >= 0 else f'RSP{ret_off:#x}'

                items.append({
                    'values': [offset_str, ret_addr_str, '    Return RIP', ret_value_str, ret_desc],
                    'color': COLOR_RETADDR,
                    'bold': False,
                    'section_id': f'return_{frame_idx}'
                })
            else:
                items.append({
                    'values': ['', '', '    Return RIP', '(not available)', ''],
                    'color': COLOR_RETADDR,
                    'bold': False,
                    'section_id': f'return_{frame_idx}'
                })

            # Stack Frame (show first 10 qwords max)
            if stack_size > 0:
                items.append({
                    'values': ['', '', f'  ▼ Stack Frame ({stack_size:#x} bytes)', '', ''],
                    'color': QtGui.QColor(220, 220, 220),
                    'bold': True,
                    'is_section_header': True,
                    'section_id': f'stack_{frame_idx}'
                })

                offset = stack_size - 8
                qword_idx = 0

                while offset >= 0:
                    addr = rsp_value + offset if rsp_value else 0
                    addr_str = f'{addr:016X}' if addr else ''
                    value_str, value_chain = self._read_qword(
                        addr) if rsp_value else ('', [])
                    value_desc = self._get_addr_info(
                        value_chain[0]) if value_chain else ''
                    items.append({
                        'values': [f'RSP+{offset:#x}', addr_str, f'    var_{offset:X}', value_str, value_desc],
                        'color': QtGui.QColor(230, 255, 230),
                        'bold': False,
                        'section_id': f'stack_{frame_idx}'
                    })
                    offset -= 8
                    qword_idx += 1

        return items

    def _get_stack_size(self, func):
        """Get stack allocation size"""
        ea = func.start_ea
        end = min(func.end_ea, ea + 100)

        while ea < end:
            mnem = idc.print_insn_mnem(ea)

            if mnem == "sub":
                op0 = idc.print_operand(ea, 0)
                op1 = idc.print_operand(ea, 1)

                if "sp" in op0.lower():
                    try:
                        # Extract immediate value
                        size = idc.get_operand_value(ea, 1)
                        return size
                    except:
                        pass

            ea = idc.next_head(ea, end)

        return 0x20  # Default

    def _is_64bit(self):
        """Check if 64-bit binary"""
        try:
            return ida_ida.inf_is_64bit()
        except:
            # Fallback
            info = idc.get_inf_attr(idc.INF_PROCNAME)
            return "64" in str(info) or idc.get_inf_attr(idc.INF_LFLAGS) & 0x10

    def _get_rsp(self):
        """Get RSP register value if debugger active"""
        try:
            if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
                return idc.get_reg_value('RSP')
        except:
            pass
        return None

    def _read_qword(self, addr):
        """Read qword from memory with dereferencing chain - returns (display_str, addr_list)"""
        if not addr:
            return '', []
        try:
            value = idc.get_qword(addr)
            if not value:
                return '0000000000000000', []

            # Build dereferencing chain
            chain = [f'{value:016X}']
            addr_list = [value]  # Track addresses for click handling
            current = value

            # Dereference up to 3 times
            for i in range(3):
                if current < 0x10000 or current > 0x7FFFFFFFFFFF:
                    break

                # Check if current address points to a string
                string_val = self._try_read_string(current)
                if string_val:
                    # Add annotation for current address
                    info = self._get_addr_info(current)
                    if info:
                        chain.append(info)
                    # Add string representation
                    chain.append(f'("{string_val}")')
                    break

                # Try to read next value
                try:
                    next_val = idc.get_qword(current)
                    if next_val and next_val != current:
                        # Add annotation for current address
                        info = self._get_addr_info(current)
                        if info:
                            chain.append(info)

                        # Continue chain
                        chain.append(f'{next_val:016X}')
                        addr_list.append(next_val)
                        current = next_val
                    else:
                        # Dead end - just annotate
                        info = self._get_addr_info(current)
                        if info:
                            chain.append(info)
                        break
                except:
                    break

            return ' → '.join(chain), addr_list
        except:
            return '', []
    
    def _try_read_string(self, addr, max_len=50):
        """Try to read ASCII/Unicode string from address"""
        if not addr or addr < 0x10000:
            return None
        
        try:
            # Try ASCII string first
            ascii_str = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C)
            if ascii_str:
                s = ascii_str.decode('utf-8', errors='ignore')
                if len(s) >= 4 and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:20]):
                    if len(s) > max_len:
                        return s[:max_len] + '...'
                    return s
            
            # Try wide string (UTF-16)
            wide_str = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C_16)
            if wide_str:
                s = wide_str.decode('utf-16le', errors='ignore')
                if len(s) >= 4 and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:20]):
                    if len(s) > max_len:
                        return s[:max_len] + '...'
                    return s
            
            # Manual ASCII check - read bytes directly
            bytes_data = idc.get_bytes(addr, min(max_len + 10, 100))
            if bytes_data:
                # Look for null-terminated ASCII
                null_idx = bytes_data.find(b'\x00')
                if null_idx > 3:
                    s = bytes_data[:null_idx].decode('utf-8', errors='ignore')
                    if all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s):
                        if len(s) > max_len:
                            return s[:max_len] + '...'
                        return s
        except:
            pass
        
        return None

    def _get_addr_info(self, addr):
        """Get rich info about an address"""
        if not addr or addr < 0x10000:
            return None

        try:
            parts = []

            # Get segment/module
            seg_name = idc.get_segm_name(addr)
            if seg_name:
                parts.append(seg_name)

            # Get function name and offset
            func = ida_funcs.get_func(addr)
            if func:
                func_name = ida_funcs.get_func_name(func.start_ea)
                offset = addr - func.start_ea
                if offset > 0:
                    parts.append(f'{func_name}+{offset:X}')
                else:
                    parts.append(func_name)

                # If it's code, try to get instruction
                if seg_name and 'text' in seg_name.lower():
                    try:
                        disasm = idc.GetDisasm(addr)
                        if disasm and len(disasm) < 50:
                            parts.append(disasm)
                    except:
                        pass

            if parts:
                return f'({" | ".join(parts)})'

            return None
        except:
            return None

    def _describe_value(self, value_str):
        """Describe what the value might be - now handled in _read_qword"""
        # Legacy method - description now in value column
        return ''

    def _on_cell_single_clicked(self, row, col):
        """Handle single click for collapsing sections"""
        try:
            if row >= len(self.items):
                return

            item = self.items[row]
            
            # Handle frame header - collapse/expand all child sections
            if item.get('is_frame_header'):
                # Find all child sections
                frame_sections = []
                for i in range(row + 1, len(self.items)):
                    child_item = self.items[i]
                    # Stop at next frame
                    if child_item.get('is_frame_header'):
                        break
                    # Collect section IDs
                    if child_item.get('is_section_header'):
                        section_id = child_item.get('section_id')
                        if section_id:
                            frame_sections.append((i, section_id))
                
                if not frame_sections:
                    return
                
                # Check if any section is expanded
                any_expanded = any(sid not in self.collapsed_sections for _, sid in frame_sections)
                
                # Toggle all sections
                for section_row, section_id in frame_sections:
                    section_item = self.items[section_row]
                    
                    if any_expanded:
                        # Collapse all
                        self.collapsed_sections.add(section_id)
                        new_text = section_item['values'][2].replace('▼', '▶')
                    else:
                        # Expand all
                        if section_id in self.collapsed_sections:
                            self.collapsed_sections.remove(section_id)
                        new_text = section_item['values'][2].replace('▶', '▼')
                    
                    # Update section header text (column 0 since it's spanned)
                    cell = self.table.item(section_row, 0)
                    if cell:
                        cell.setText(new_text)
                    
                    # Show/hide section children
                    for i in range(section_row + 1, len(self.items)):
                        child_item = self.items[i]
                        if child_item.get('is_section_header') or child_item.get('is_frame_header'):
                            break
                        self.table.setRowHidden(i, any_expanded)
                
                return

            # Check if this is a collapsible section header
            if not item.get('is_section_header'):
                return

            # Toggle collapsed state
            section_id = item.get('section_id')
            if not section_id:
                return

            is_collapsed = section_id in self.collapsed_sections

            if is_collapsed:
                self.collapsed_sections.remove(section_id)
                # Change ▶ to ▼
                new_text = item['values'][2].replace('▶', '▼')
            else:
                self.collapsed_sections.add(section_id)
                # Change ▼ to ▶
                new_text = item['values'][2].replace('▼', '▶')

            # Update header text (column 0 since it's spanned)
            cell = self.table.item(row, 0)
            if cell:
                cell.setText(new_text)

            # Show/hide children
            for i in range(row + 1, len(self.items)):
                child_item = self.items[i]

                # Stop at next section or frame
                if child_item.get('is_section_header') or child_item.get('is_frame_header'):
                    break

                # Toggle visibility
                self.table.setRowHidden(i, not is_collapsed)

        except Exception as e:
            print(f"✗ Collapse error: {e}")

    def _on_cell_clicked(self, row, col):
        """Handle cell double-click to jump to address"""
        try:
            cell = self.table.item(row, col)
            if not cell:
                return

            text = cell.text().strip()
            if not text:
                return

            # Column 0: Offset (RSP+0x...)
            if col == 0 and text.startswith('RSP+'):
                try:
                    offset_str = text[4:]  # Remove "RSP+"
                    offset = int(offset_str, 16)
                    rsp = self._get_rsp()
                    if rsp:
                        addr = rsp + offset
                        idc.jumpto(addr)
                        print(f"✓ Jumped to stack: {addr:#x}")
                except:
                    pass

            # Column 1: Address (absolute address on stack)
            elif col == 1:
                try:
                    # Parse hex address
                    addr = int(text, 16)
                    if addr > 0x10000:
                        idc.jumpto(addr)
                        print(f"✓ Jumped to: {addr:#x}")
                except:
                    pass

            # Column 3: Value (hex address with possible arrows and annotations)
            elif col == 3:
                try:
                    # Parse format: "00007FFCFD9FE8D7 → (kernel32.dll) → 05C88815FF48C868"
                    # Extract first hex value
                    parts = text.split('→')
                    if parts:
                        # Get first part and remove any annotations
                        first_part = parts[0].strip()
                        # Remove anything in parentheses
                        first_part = first_part.split('(')[0].strip()

                        # Try to parse as hex
                        value = int(first_part, 16)
                        if value > 0x10000:
                            idc.jumpto(value)
                            print(f"✓ Jumped to: {value:#x}")
                except Exception as e:
                    # Fallback: try to find any hex pattern
                    import re
                    hex_match = re.search(r'[0-9A-Fa-f]{8,16}', text)
                    if hex_match:
                        try:
                            value = int(hex_match.group(), 16)
                            if value > 0x10000:
                                idc.jumpto(value)
                                print(f"✓ Jumped to: {value:#x}")
                        except:
                            pass

            # Column 4: Description (→ function_name)
            elif col == 4 and '→' in text:
                try:
                    func_name = text.split('→')[1].strip()
                    addr = idc.get_name_ea_simple(func_name)
                    if addr != idc.BADADDR:
                        idc.jumpto(addr)
                        print(f"✓ Jumped to {func_name}: {addr:#x}")
                except:
                    pass

        except Exception as e:
            print(f"✗ Jump failed: {e}")

    def _show_context_menu(self, pos):
        """Show context menu for cells with multiple addresses"""
        try:
            item = self.table.itemAt(pos)
            if not item:
                return

            text = item.text().strip()
            col = item.column()

            # Only for value column with arrows
            if col != 3 or '→' not in text:
                return

            # Extract all hex addresses from chain
            import re
            addresses = []
            parts = text.split('→')

            for part in parts:
                # Remove annotations in parentheses
                clean = re.sub(r'\([^)]+\)', '', part).strip()
                # Find hex values
                hex_matches = re.findall(r'[0-9A-Fa-f]{8,16}', clean)
                for hex_str in hex_matches:
                    try:
                        addr = int(hex_str, 16)
                        if addr > 0x10000:
                            addresses.append((hex_str, addr))
                    except:
                        pass

            if len(addresses) <= 1:
                return  # No menu needed

            # Create context menu
            menu = QtWidgets.QMenu(self.parent)

            for hex_str, addr in addresses:
                # Get info for this address
                info = self._get_addr_info(addr)
                label = f"Jump to {hex_str}"
                if info:
                    label += f" {info}"

                action = menu.addAction(label)
                action.triggered.connect(
                    lambda checked, a=addr: self._jump_to(a))

            # Show menu at cursor
            menu.exec_(self.table.viewport().mapToGlobal(pos))

        except Exception as e:
            print(f"✗ Context menu error: {e}")

    def _jump_to(self, addr):
        """Jump to address"""
        try:
            idc.jumpto(addr)
            print(f"✓ Jumped to: {addr:#x}")
        except Exception as e:
            print(f"✗ Jump failed: {e}")

    def OnClose(self, form):
        """Cleanup"""
        if self.dbg_hook:
            self.dbg_hook.unhook()
            self.dbg_hook = None


def show_viewer():
    """Show stack viewer"""
    viewer = SimpleStackViewer()
    viewer.Show("Stack Frame Viewer")
    return viewer


# Action handler for hotkey
class StackViewerAction(ida_kernwin.action_handler_t):
    """Action handler for opening stack viewer"""

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        """Called when action is triggered"""
        show_viewer()
        return 1

    def update(self, ctx):
        """Check if action should be enabled"""
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_hotkey():
    """Register hotkey for stack viewer"""
    action_name = "stackviewer:show"

    # Unregister if exists
    ida_kernwin.unregister_action(action_name)

    # Create action descriptor
    action_desc = ida_kernwin.action_desc_t(
        action_name,                    # Action name
        "Stack Frame Viewer",           # Label
        StackViewerAction(),            # Handler
        "Ctrl+Shift+K",                 # Hotkey
        "Show call stack with frames",  # Tooltip
        199                             # Icon (stack icon)
    )

    # Register action
    if ida_kernwin.register_action(action_desc):
        # Attach to View menu
        ida_kernwin.attach_action_to_menu(
            "View/Open subviews/", action_name, ida_kernwin.SETMENU_APP)
        return True
    else:
        return False


# IDA Plugin Class
class StackViewerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "View stack frames with full call stack - Double-click to jump"
    help = "Press Ctrl+Shift+K to open"
    wanted_name = "Stack Frame Viewer"
    wanted_hotkey = ""  # Hotkey registered via action, not plugin

    def init(self):
        """Initialize plugin"""
        if register_hotkey():
            print("✓ Stack Frame Viewer loaded - Ctrl+Shift+K (double-click to jump)")
            return ida_idaapi.PLUGIN_KEEP
        return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        """Run plugin"""
        show_viewer()

    def term(self):
        """Terminate plugin"""
        ida_kernwin.unregister_action("stackviewer:show")


def PLUGIN_ENTRY():
    return StackViewerPlugin()
