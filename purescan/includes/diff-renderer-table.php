<?php
/**
 * PureScan – Ultimate Fixed Diff Renderer (Line Numbers + Full Background Colors)
 * Complete solution: Right-side line numbers always displayed + full background color for both columns
 */
if (!class_exists('Text_Diff_Renderer')) {
    return;
}


if (!class_exists('PureScan_Text_Diff_Renderer_Table')) {
    class PureScan_Text_Diff_Renderer_Table extends Text_Diff_Renderer {
        private $line_old = 0;
        private $line_new = 0;
        public function render($diff) {
            $this->line_old = 0;
            $this->line_new = 0;
            $html = '';
            foreach ($diff->getDiff() as $edit) {
                $class = get_class($edit);
                if (strpos($class, 'Text_Diff_Op_') !== 0) continue;
                $type = strtolower(substr($class, 13)); // copy, add, delete, change
                $method = '_' . $type;
                if (method_exists($this, $method)) {
                    $html .= $this->$method($edit);
                }
            }
            return $html;
        }
        private function _copy($edit) {
            $html = '';
            foreach ($edit->orig as $line) {
                $this->line_old++;
                $this->line_new++;
                $html .= $this->row($this->line_old, $line, $this->line_new, $line, 'context');
            }
            return $html;
        }
        private function _delete($edit) {
            $html = '';
            foreach ($edit->orig as $line) {
                $this->line_old++;
                $html .= $this->row($this->line_old, $line, null, '', 'deleted');
            }
            return $html;
        }
        private function _add($edit) {
            $html = '';
            foreach ($edit->final as $line) {
                $this->line_new++;
                $html .= $this->row(null, '', $this->line_new, $line, 'added');
            }
            return $html;
        }
        private function _change($edit) {
            $html = '';
            $old_lines = $edit->orig ?? [];
            $new_lines = $edit->final ?? [];
            $max = max(count($old_lines), count($new_lines));
            for ($i = 0; $i < $max; $i++) {
                $old_line = $old_lines[$i] ?? '';
                $new_line = $new_lines[$i] ?? '';
                $old_num = $old_line !== '' ? (++$this->line_old) : null;
                $new_num = $new_line !== '' ? (++$this->line_new) : null;
                if ($old_line !== '' && $new_line !== '') {
                    $type = 'change';
                } elseif ($old_line !== '') {
                    $type = 'deleted';
                } else {
                    $type = 'added';
                }
                $html .= $this->row($old_num, $old_line, $new_num, $new_line, $type);
            }
            return $html;
        }
        private function row($num_old, $old, $num_new, $new, $type = 'context') {
            $old_code = $old !== '' ? htmlspecialchars($old, ENT_NOQUOTES) : '&nbsp;';
            $new_code = $new !== '' ? htmlspecialchars($new, ENT_NOQUOTES) : '&nbsp;';
   
            switch ($type) {
                case 'deleted':
                    $class_old = 'deleted';
                    $class_new = 'empty';
                    break;
   
                case 'added':
                    $class_old = 'empty';
                    $class_new = 'added';
                    break;
   
                case 'change':
                    $class_old = 'changed-old';
                    $class_new = 'changed-new';
                    break;
   
                default:
                    $class_old = 'context';
                    $class_new = 'context';
            }
   
            $num_old_display = $num_old !== null ? $num_old : '';
            $num_new_display = $num_new !== null ? $num_new : '';
   
            return "<tr>
                <td class='line-num'>{$num_old_display}</td>
                <td class='code {$class_old}'>{$old_code}</td>
                <td class='line-num'>{$num_new_display}</td>
                <td class='code {$class_new}'>{$new_code}</td>
            </tr>";
        }
    }
}