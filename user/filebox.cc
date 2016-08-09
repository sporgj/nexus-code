#include <string>
#include "filebox.h"

using namespace std;

class fbox;

FileBox::FileBox()
{
    this->fbox_ptr = new fbox();
    this->fd = nullptr;

    fbox_ptr->set_count(0);
    fbox_ptr->clear_ekey();
    fbox_ptr->clear_mac();
}

FileBox * FileBox::from_file(const char * fpath, bool readonly)
{
    FileBox * object = nullptr;
    fbox * _fbox = new class ::fbox();
    fstream * input = new fstream(
        fpath, ios::binary | (readonly ? ios::in : ios::in | ios::out));

    if (!_fbox->ParseFromIstream(input)) {
        cerr << "Could not parse from '" << fpath << "'" << endl;
        goto out;
    }

    input->close();

    object = new FileBox(_fbox);

out:
    return object;
}

bool FileBox::add(encoded_fname_t * encoded_fname, raw_fname_t * raw_fname,
                  crypto_iv_t * iv)
{
    class ::fbox_fentry * fentry = fbox_ptr->add_files();
    fentry->set_encoded_name(encoded_fname, sizeof(encoded_fname_t));
    fentry->set_raw_name(raw_fname, raw_fname->len + sizeof(raw_fname->len));
    fentry->set_iv(iv, sizeof(crypto_iv_t));

    uint32_t count = fbox_ptr->count();
    fbox_ptr->set_count(++count);

    return true;
}

bool FileBox::write(FileBox * fb, fstream * fd)
{
    return fb->fbox_ptr->SerializeToOstream(fd);
}

bool FileBox::write(FileBox * fb, const char * fpath)
{
    fstream input(fpath, ios::in | ios::out | ios::trunc);
    bool rv = FileBox::write(fb, &input);
    input.close();

    return rv;
}
