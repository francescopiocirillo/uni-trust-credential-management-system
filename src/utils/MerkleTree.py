import hashlib
from cryptography.fernet import Fernet

class MerkleTree:

    def __init__(self, data_list):
        self.root, self.tree = self.build_merkle_tree(data_list)

    @staticmethod
    def sha256(data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def build_merkle_tree(self, data_list):
        leaves = [MerkleTree.sha256(data) for data in data_list]
        tree = [leaves]

        while len(tree[-1]) > 1:
            current_level = tree[-1]
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            next_level = [
                MerkleTree.sha256(current_level[i] + current_level[i + 1])
                for i in range(0, len(current_level), 2)
            ]
            tree.append(next_level)

        return tree[-1][0], tree  # Merkle root e tree

    def verify_data(decrypted_data, leaf_index, merkle_root, leaves, tree):
        data_hash = MerkleTree.sha256(decrypted_data)
        if data_hash != leaves[leaf_index]:
            return False

        current_hash = data_hash
        for level in tree[:-1]:
            if leaf_index % 2 == 0:
                sibling_index = leaf_index + 1
            else:
                sibling_index = leaf_index - 1

            sibling_hash = (
                level[sibling_index]
                if sibling_index < len(level)
                else level[-1]
            )

            if leaf_index % 2 == 0:
                current_hash = MerkleTree.sha256(current_hash + sibling_hash)
            else:
                current_hash = MerkleTree.sha256(sibling_hash + current_hash)

            leaf_index //= 2

        return current_hash == merkle_root

    def get_merkle_proof(self, leaf_index: int):
        """
        Restituisce la proof per la foglia con indice `leaf_index`.

        Output: lista di dizionari,
                es. [{'hash': <sibling>, 'direction': 'right'}, …]
                direction indica dove sta il *sibling* rispetto
                al nodo in questione.
        """
        proof = []

        for level in self.tree[:-1]:  # si ferma prima della root
            if leaf_index % 2 == 0:  # foglia a sinistra
                sibling_index = leaf_index + 1
                direction = "right"
            else:  # foglia a destra
                sibling_index = leaf_index - 1
                direction = "left"

            # se abbiamo duplicato l’ultimo nodo per padding
            if sibling_index >= len(level):
                sibling_index = len(level) - 1

            proof.append(
                {"hash": level[sibling_index], "direction": direction}
            )
            leaf_index //= 2  # risali di livello

        return proof

    @staticmethod
    def verify_data_with_proof(data: str, proof, merkle_root: str) -> bool:
        """
        Ricostruisce la root partendo dal dato e dalla proof.
        Ritorna True se combacia con `merkle_root`.
        """
        current_hash = MerkleTree.sha256(data)
        for p in proof:
            if p["direction"] == "right":
                current_hash = MerkleTree.sha256(current_hash + p["hash"])
            else:  # left
                current_hash = MerkleTree.sha256(p["hash"] + current_hash)
        return current_hash == merkle_root
"""

    def fernet_encrypt(data, key):
        fernet = Fernet(key)
        return fernet.encrypt(data.encode('utf-8'))


    def fernet_decrypt(encrypted_data, key):
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode('utf-8')
if __name__ == "__main__":
    data_list = [
        "message_1", "message_2", "message_3", "message_4",
        "message_5", "message_6", "message_7", "message_8"
    ]

    merkle_root, tree = build_merkle_tree(data_list)
    key = Fernet.generate_key()

    encrypted_data = [fernet_encrypt(data, key) for data in data_list]
    leaf_index = 5
    decrypted_data = fernet_decrypt(encrypted_data[leaf_index], key)

    print(f"Decrypted data: {decrypted_data}")

    if verify_data(decrypted_data, leaf_index, merkle_root, tree[0], tree):
        print(f"Data '{decrypted_data}' is verified using the Merkle tree!")
    else:
        print(f"Data verification failed for '{decrypted_data}'!")
"""