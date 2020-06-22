from cryptography.fernet import Fernet
import json
import os


class DictoCrypto:

    """
    Wrapper class to hold encryption and decryption methods.

    """

    @staticmethod
    def encrypt_data(data: str or dict,
                     save_path: str = None,
                     description: str = None) -> None:
        """
        Takes some data (dict or str), and generates a fernet key.
        It then encrypts the data using the key, and saves the data 
        down as a '.txt' file at the save path using the description 
        to name the file.

        Also saves the key file as a '.txt' file at the save_path 
        using the description to name the file.


        Args:
        data (str or dict): Data to be encrypted, like an api key, or
        set of other credentials that you don't wish to share.

        save_path(str, optional): Must be a valid path or will raise
        OSError. Otherwise uses current working directory.

        description(str, optional): a description for your secret data, 
        defaults to 'secretfile'.

        Returns:
        None

        """

        if save_path is None:
            # use current working directory if not given
            save_path = os.getcwd()
        else:
            # check if the path is valid and raise Error if not.
            if not os.path.isdir(save_path):
                raise OSError("No such path.")

        if description is None:
            # use a boring obvious name!
            description = 'secretfile'

        if isinstance(data, dict):
            # convert to string/JSON if data is a dict.
            data = json.dumps(data)

        # Generate a Fernet key
        key = Fernet.generate_key()
        my_fernet = Fernet(key)

        # encrypt the data
        encrypted_data = my_fernet.encrypt(
            bytes(data, encoding='utf-8'))

        # Write encryption key to file
        key_path = f'{save_path}' + '/'+f'{description}-key.txt'
        data_path = f'{save_path}' + '/'+f'{description}.txt'

        with open(key_path, 'wb') as f:
            f.write(key)
            f.close()
        print(key_path, "\n saved successfully")

        # write encrypted file to file
        with open(data_path, 'wb') as f:
            f.write(encrypted_data)
            f.close()
        print(data_path, "\n saved successfully")

    @staticmethod
    def decrypt_data(key_filepath: str,
                     encrypted_filepath: str) -> dict or str:
        """
        Takes an encrypted data file, unencrypts and returns it.
        (encrypted by the encrypt data method in this class)



        Parameters:

        encrypted_filepath(str): path to a fernet key, has to be 
        utf-8


        encrypted_filepath(str): path to a file to decrypt, has to be
        utf-8 encoded string, and encrypted using the key within the 



        Returns (dict or str):
        unencrypted data, will attempt to parse as json and return a
        string if this fails.


        """

        def open_as_bytestring(path: str) -> bytes:
            """ opens a text file or similar
            in read-only mode and parses it
            to bytes in utf-8 encoding

            Args:
                path (str): path to the file

            Returns:
                bytes: the contents of the file
                as utf-8 bytes
            """
            with open(path, "r") as f:
                return bytes(f.read(), 'utf-8')

        my_key = open_as_bytestring(path=key_filepath)
        my_file = open_as_bytestring(path=encrypted_filepath)

        my_fernet = Fernet(my_key)

        data = my_fernet.decrypt(my_file).decode('utf-8')
        try:
            # attempt to convert to dictionary
            return json.loads(data)
        except json.JSONDecodeError:
            # if it falls
            return data
